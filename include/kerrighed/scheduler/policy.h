#ifndef __KRG_SCHEDULER_POLICY_H__
#define __KRG_SCHEDULER_POLICY_H__

#include <linux/configfs.h>
#include <linux/list.h>
#include <kerrighed/sys/types.h>
#include <kerrighed/scheduler/global_config.h>

struct task_struct;

/**
 * This structure represents pluggable scheduling policies for distributing
 * load in the cluster based on data measured by probes (e.g. CPU usage, memory
 * usage, ...). User can implement these scheduling policies as separate Linux
 * kernel modules and inserts them dynamcally into kernel. By doing this, it
 * extends set of scheduling algorithms for distributing load across the
 * cluster.
 * @author Marko Novak, Louis Rilling
 */
struct scheduler_policy {
	struct config_group group; /** representation of scheduling policy in
				     ConfigFS. */
	spinlock_t lock; /** lock for synchronizing scheduling policy access. */
	struct global_config_item global_item; /** global_config subsystem */
	struct global_config_attrs global_attrs;
};

/** struct which contains each policy's operations. */
struct scheduler_policy_operations {
	struct scheduler_policy *(*new)(const char *name); /* sched policy
							     * constructor */
	void (*destroy)(struct scheduler_policy *policy); /* sched policy
							   * destructor */
	/* notifier of node set changes */
	void (*update_node_set)(struct scheduler_policy *policy,
				const krgnodemask_t *new_set,
				const krgnodemask_t *removed_set,
				const krgnodemask_t *added_set);
	/* process placement function
	 * called when a task attached to this policy creates a new task */
	kerrighed_node_t (*new_task_node)(struct scheduler_policy *policy,
					  struct task_struct *parent);
};

/* Same limitation as configfs (see SIMPLE_ATTR_SIZE in fs/configfs/file.c) */
#define SCHEDULER_POLICY_ATTR_SIZE 4096

/*
 * This struct is used for representing scheduling policies' attributes.
 * It contains attribute-specific functions for reading and storing attribute
 * value.
 */
struct scheduler_policy_attribute {
	struct configfs_attribute attr;

	/** function for reading attribute's value */
	ssize_t (*show)(struct scheduler_policy *, char *);
	/** function for storing attribute's value */
	ssize_t (*store)(struct scheduler_policy *, const char *, size_t);

	/** allow a parameter to be strictly local */
	int local;
};

/*
 * To be initialized with SCHEDULER_POLICY_TYPE[_INIT]. The sched policy
 * subsystem will complete init at registration.
 */
struct scheduler_policy_type {
	const char *name;
	struct config_item_type item_type;
	struct scheduler_policy_operations *ops;
	struct scheduler_policy_attribute **attrs;
	struct list_head list;	/** list of registered sched policy types */
};

/**
 * Mandatory macro to define a scheduling policy type. Can be used through the
 * SCHEDULER_POLICY_TYPE macro.
 *
 * @param owner		Module defining the scheduler_policy type
 * @param _name		Unique name for the scheduler_policy type
 * @param _ops		scheduler_policy_operations for this type
 * @param _attrs	NULL-terminated array of scheduler_policy_attribute,
 *			or NULL
 */
#define SCHEDULER_POLICY_TYPE_INIT(owner, _name, _ops, _attrs) \
	{						       \
		.name = _name,				       \
		.item_type = { .ct_owner = owner, },	       \
		.ops = _ops,				       \
		.attrs = _attrs,			       \
	}

/**
 * Convenience macro to define a scheduling policy type.
 *
 * @param var		Name of the variable containing the type
 * @param name		Unique name of the scheduler_policy type
 * @param ops		scheduler_policy_operations for this type
 * @param attrs		NULL-terminated array of scheduler_policy_attribute,
 *			or NULL
 */
#define SCHEDULER_POLICY_TYPE(var, name, ops, attrs)			  \
	struct scheduler_policy_type var =				  \
		SCHEDULER_POLICY_TYPE_INIT(THIS_MODULE, name, ops, attrs)

/**
 * This function initializes a new scheduling policy. Must be called by
 * scheduler_policy constructors.
 * @author Marko Novak, Louis Rilling
 *
 * @param policy	pointer to the scheduler_policy to init
 * @param name		name of the scheduling policy. This name must be the one
 *			provided as argument to the constructor.
 * @param type		type of the scheduler_policy
 * @param def_groups	NULL-terminated array of subdirs of the scheduler_policy
 *			directory, or NULL
 *
 * @return		0 if successul,
 *			-ENODEV is module is unloading (should not happen!),
 *			-ENOMEM if not sufficient memory could be allocated.
 */
int scheduler_policy_init(struct scheduler_policy *policy,
			  const char *name,
			  struct scheduler_policy_type *type,
			  struct config_group *def_groups[]);

/**
 * This function frees all the memory taken by a scheduling policy. Must be
 * called by the scheduler_policy destructor.
 * @author Marko Novak, Louis Rilling
 *
 * @param policy	pointer to scheduler_policy whose memory we want to free
 */
void scheduler_policy_cleanup(struct scheduler_policy *policy);

/**
 * Get a reference on a sched policy
 *
 * @param policy	sched policy to get a reference on
 */
static inline void scheduler_policy_get(struct scheduler_policy *policy)
{
	if (policy)
		config_group_get(&policy->group);
}

/**
 * Put a reference on a sched policy
 *
 * @param policy	sched policy which reference to put
 */
static inline void scheduler_policy_put(struct scheduler_policy *policy)
{
	if (policy)
		config_group_put(&policy->group);
}

/**
 * Notify a policy that its node set was updated
 * Called with the scheduler's node set mutex locked.
 *
 * @param policy	policy to notify
 * @param new_set	new node set of the policy
 * @param removed_set	nodes just removed from the set
 * @param added_set	nodes just added to the set
 */
static inline
void scheduler_policy_update_node_set(struct scheduler_policy *policy,
				      const krgnodemask_t *new_set,
				      const krgnodemask_t *removed_set,
				      const krgnodemask_t *added_set)
{
	struct scheduler_policy_type *type =
		container_of(policy->group.cg_item.ci_type,
			     struct scheduler_policy_type, item_type);
	if (type->ops->update_node_set)
		type->ops->update_node_set(policy,
					   new_set,
					   removed_set,
					   added_set);
}

/**
 * Compute the best node to place a new task created by parent according to this
 * scheduling policy
 * The new task may not be created on the selected node at all, since another
 * scheduling policy attached to the same task may decide differently and win.
 *
 * @author Marko Novak, Louis Rilling
 *
 * @param policy	policy that is consulted
 * @param parent	parent of the task to be created
 */
static inline
kerrighed_node_t scheduler_policy_new_task_node(struct scheduler_policy *policy,
						struct task_struct *parent)
{
	struct scheduler_policy_type *type =
		container_of(policy->group.cg_item.ci_type,
			     struct scheduler_policy_type, item_type);
	if (type->ops->new_task_node)
		return type->ops->new_task_node(policy, parent);
	return KERRIGHED_NODE_ID_NONE;
}

/**
 * This function is used for registering newly added scheduling policy types.
 * Once a type is registered, new scheduling policies of this type can be
 * created when user does mkdir with the type name.
 * @author Marko Novak, Louis Rilling
 *
 * @param type		pointer to the scheduling policy type to register.
 *
 * @return		0 if successful,
 *			-EEXIST if scheduling policy type with the same name
 *				is already registered.
 */
int scheduler_policy_type_register(struct scheduler_policy_type *type);

/**
 * This function is used for removing scheduling policy registrations.
 * Must *only* be called at module unloading.
 * @author Marko Novak, Louis Rilling
 *
 * @param type		pointer to the scheduling policy type to unregister.
 */
void scheduler_policy_type_unregister(struct scheduler_policy_type *type);

#endif /* __KRG_SCHEDULER_POLICY_H__ */
