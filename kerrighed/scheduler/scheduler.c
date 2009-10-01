/*
 *  kerrighed/scheduler/scheduler.c
 *
 *  Copyright (C) 2007 Marko Novak - Xlab
 *  Copyright (C) 2007-2008 Louis Rilling - Kerlabs
 */

#include <linux/configfs.h>
#include <linux/module.h>
#include <linux/nsproxy.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/err.h>
#include <kerrighed/krgflags.h>
#include <kerrighed/krgnodemask.h>
#include <kerrighed/scheduler/policy.h>
#include <kerrighed/scheduler/process_set.h>
#include <kerrighed/scheduler/global_config.h>

#include "internal.h"

/*
 * Structure representing a scheduler.
 * Created each time a user does mkdir in "schedulers" subsystem directory,
 * and destroyed after user does rmdir on the matching directory.
 */
struct scheduler {
	struct config_group group;	 /** configfs reprensentation */
	struct scheduler_policy *policy; /** scheduling policy attached to this
					  * scheduler */
	struct process_set *processes;	 /** set of processes managed by this
					  * scheduler */
	struct config_group *default_groups[2]; /** default subdirs */
	struct global_config_item global_item; /** global_config subsystem */

	krgnodemask_t node_set;
	struct mutex node_set_mutex;
	int node_set_exclusive;

	struct list_head list;

	spinlock_t lock;
};

static inline struct scheduler *to_scheduler(struct config_item *item)
{
	return container_of(item, struct scheduler, group.cg_item);
}

#define SCHEDULER_ATTR_SIZE 4096

struct scheduler_attribute {
	struct configfs_attribute config;
	ssize_t (*show)(struct scheduler *,
			char *);
	ssize_t (*store)(struct scheduler *,
			 const char *,
			 size_t count);
};

static inline
struct scheduler_attribute *
to_scheduler_attribute(struct configfs_attribute *attr)
{
	return container_of(attr, struct scheduler_attribute, config);
}

static LIST_HEAD(schedulers_head);
static DEFINE_SPINLOCK(schedulers_list_lock);

static krgnodemask_t exclusive_set;

void scheduler_get(struct scheduler *scheduler)
{
	if (scheduler)
		config_group_get(&scheduler->group);
}
EXPORT_SYMBOL(scheduler_get);

void scheduler_put(struct scheduler *scheduler)
{
	if (scheduler)
		config_group_put(&scheduler->group);
}
EXPORT_SYMBOL(scheduler_put);

static inline struct scheduler *get_parent_scheduler(struct config_item *item)
{
	struct config_item *scheduler_item;
	scheduler_item = config_item_get(item->ci_parent);
	if (scheduler_item)
		return to_scheduler(scheduler_item);
	return NULL;
}

struct scheduler *
scheduler_policy_get_scheduler(struct scheduler_policy *policy)
{
	return get_parent_scheduler(&policy->group.cg_item);
}
EXPORT_SYMBOL(scheduler_policy_get_scheduler);

struct scheduler *process_set_get_scheduler(struct process_set *pset)
{
	return get_parent_scheduler(&pset->group.cg_item);
}
EXPORT_SYMBOL(process_set_get_scheduler);

struct scheduler_policy *
scheduler_get_scheduler_policy(struct scheduler *scheduler)
{
	struct scheduler_policy *policy;

	spin_lock(&scheduler->lock);
	scheduler_policy_get(scheduler->policy);
	policy = scheduler->policy;
	spin_unlock(&scheduler->lock);

	return policy;
}
EXPORT_SYMBOL(scheduler_get_scheduler_policy);

struct process_set *scheduler_get_process_set(struct scheduler *scheduler)
{
	struct process_set *pset;

	spin_lock(&scheduler->lock);
	process_set_get(scheduler->processes);
	pset = scheduler->processes;
	spin_unlock(&scheduler->lock);

	return pset;
}
EXPORT_SYMBOL(scheduler_get_process_set);

void scheduler_get_node_set(struct scheduler *scheduler,
			    krgnodemask_t *node_set)
{
	__krgnodes_copy(node_set, &scheduler->node_set);
}
EXPORT_SYMBOL(scheduler_get_node_set);

static ssize_t scheduler_show_attribute(struct config_item *item,
				        struct configfs_attribute *attr,
				        char *page)
{
	struct scheduler_attribute *sa = to_scheduler_attribute(attr);
	ssize_t ret = -EACCES;
	if (sa->show)
		ret = sa->show(to_scheduler(item), page);
	return ret;
}

static ssize_t scheduler_store_attribute(struct config_item *item,
					 struct configfs_attribute *attr,
					 const char *page,
					 size_t count)
{
	struct scheduler_attribute *sa = to_scheduler_attribute(attr);
	struct string_list_object *list;
	ssize_t ret = -EACCES;

	if (!(current->flags & PF_KTHREAD) && !current->nsproxy->krg_ns)
		return -EPERM;

	if (sa->store) {
		list = global_config_attr_store_begin(item);
		if (IS_ERR(list))
			return PTR_ERR(list);

		ret = sa->store(to_scheduler(item), page, count);

		if (ret >= 0)
			ret = global_config_attr_store_end(list,
							   item, attr,
							   page, ret);
		else
			global_config_attr_store_error(list, item);
	}

	return ret;
}

static void scheduler_free(struct scheduler *);

/*
 * Configfs callback when the last reference on a scheduler is dropped.
 * Destroys the scheduler.
 */
static void scheduler_release(struct config_item *item)
{
	struct scheduler *s = to_scheduler(item);
	scheduler_free(s);
}

struct configfs_item_operations scheduler_item_ops = {
	.show_attribute = scheduler_show_attribute,
	.store_attribute = scheduler_store_attribute,
	.release = scheduler_release,
};

/**
 * Callback called by global_config when the scheduler_policy of a scheduler is
 * globally dropped
 */
static void policy_global_drop(struct global_config_item *item)
{
	struct scheduler_policy *policy =
		container_of(item, struct scheduler_policy, global_item);
	scheduler_policy_drop(policy);
}

static struct global_config_drop_operations policy_global_drop_ops = {
	.drop_func = policy_global_drop,
	.is_symlink = 0
};

/**
 * This is a configfs callback function, which is invoked every time user tries
 * to create a directory in a scheduler directory ("schedulers/<scheduler>"
 * directories).  It is used for loading scheduling policy's module, creating
 * and activating a new scheduler_policy having the type matching the new
 * directory name.
 */
static struct config_group *scheduler_make_group(struct config_group *group,
						 const char *name)
{
	struct scheduler *s = to_scheduler(&group->cg_item);
	struct config_group *ret;
	struct scheduler_policy *policy;
	struct string_list_object *global_policies;
	int err;

	ret = ERR_PTR(-EPERM);
	if (!(current->flags & PF_KTHREAD) && !current->nsproxy->krg_ns)
		goto out;

	/* Cannot manage several scheduling policies yet */
	ret = ERR_PTR(-EBUSY);
	if (s->policy)
		goto out;

	global_policies = global_config_make_item_begin(&group->cg_item, name);
	if (IS_ERR(global_policies)) {
		ret = (void *)global_policies;
		goto out;
	}

	policy = scheduler_policy_new(name);
	if (IS_ERR(policy)) {
		err = PTR_ERR(policy);
		goto err_policy;
	}
	global_config_item_init(&policy->global_item,
				&policy_global_drop_ops);
	err = global_config_make_item_end(global_policies,
					  &group->cg_item,
					  &policy->global_item,
					  name);
	if (err)
		goto err_global_end;

	spin_lock(&s->lock);
	s->policy = policy;
	spin_unlock(&s->lock);
	ret = &policy->group;

out:
	return ret;

err_policy:
	global_config_make_item_error(global_policies, name);
	ret = ERR_PTR(err);
	goto out;

err_global_end:
	scheduler_policy_drop(policy);
	ret = ERR_PTR(err);
	goto out;
}

static int scheduler_allow_drop_item(struct config_group *group,
				     struct config_item *item)
{
	if (!(current->flags & PF_KTHREAD) && !current->nsproxy->krg_ns)
		return -EPERM;
	return 0;
}

/*
 * Configfs callback called when the scheduling policy directory of a scheduler
 * is removed.
 */
static void scheduler_drop_item(struct config_group *group,
				struct config_item *item)
{
	struct scheduler *s = to_scheduler(&group->cg_item);
	struct scheduler_policy *p =
		container_of(item, struct scheduler_policy, group.cg_item);
	spin_lock(&s->lock);
	s->policy = NULL;
	spin_unlock(&s->lock);
	global_config_drop(&p->global_item);
}

/**
 * This struct is ConfigFS-specific. See ConfigFS documentation for its
 * explanation.
 */
static struct configfs_group_operations scheduler_group_ops = {
	.make_group = scheduler_make_group,
	.allow_drop_item = scheduler_allow_drop_item,
	.drop_item = scheduler_drop_item,
};

/* Scheduler attributes */

static ssize_t node_set_show(struct scheduler *s, char *page)
{
	return krgnodelist_scnprintf(page, SCHEDULER_ATTR_SIZE, s->node_set);
}

static int node_set_may_be_exclusive(const struct scheduler *s,
				     const krgnodemask_t *node_set);

static int do_update_node_set(struct scheduler *s, const krgnodemask_t *new_set)
{
	krgnodemask_t removed_set, added_set;
	struct scheduler_policy *policy = NULL;
	int err = -EBUSY;

	mutex_lock(&s->node_set_mutex);
	spin_lock(&schedulers_list_lock);
	if (s->node_set_exclusive) {
		if (!node_set_may_be_exclusive(s, new_set))
			goto unlock;
		krgnodes_andnot(exclusive_set, exclusive_set, s->node_set);
		krgnodes_or(exclusive_set, exclusive_set, *new_set);
	} else {
		if (krgnodes_intersects(exclusive_set, *new_set))
			goto unlock;
	}
	err = 0;

	krgnodes_andnot(removed_set, s->node_set, *new_set);
	krgnodes_andnot(added_set, *new_set, s->node_set);

	spin_lock(&s->lock);
	__krgnodes_copy(&s->node_set, new_set);
	policy = s->policy;
	scheduler_policy_get(policy);
	spin_unlock(&s->lock);
unlock:
	spin_unlock(&schedulers_list_lock);

	if (policy) {
		scheduler_policy_update_node_set(policy,
						 new_set,
						 &removed_set,
						 &added_set);
		scheduler_policy_put(policy);
	}
	mutex_unlock(&s->node_set_mutex);

	return err;
}

static
ssize_t node_set_store(struct scheduler *s, const char *page, size_t count)
{
	krgnodemask_t new_set;
	int err;
	ssize_t ret;

	err = krgnodelist_parse(page, new_set);
	if (err) {
		ret = err;
	} else {
		if (krgnodes_subset(new_set, krgnode_online_map)) {
			err = do_update_node_set(s, &new_set);
			ret = err ? err : count;
		} else {
			ret = -EINVAL;
		}
	}
	return ret;
}

static struct scheduler_attribute node_set = {
	.config = {
		.ca_name = "node_set",
		.ca_owner = THIS_MODULE,
		.ca_mode = S_IRUGO | S_IWUSR,
	},
	.show = node_set_show,
	.store = node_set_store
};

static ssize_t node_set_exclusive_show(struct scheduler *s, char *page)
{
	return sprintf(page, "%d", s->node_set_exclusive);
}

static int node_set_may_be_exclusive(const struct scheduler *s,
			    const krgnodemask_t *node_set)
{
	struct scheduler *pos;

	list_for_each_entry(pos, &schedulers_head, list)
		if (pos != s && krgnodes_intersects(*node_set, pos->node_set))
			return 0;
	return 1;
}

static int make_node_set_exclusive(struct scheduler *s)
{
	int err = 0;

	if (s->node_set_exclusive)
		goto out;

	if (!node_set_may_be_exclusive(s, &s->node_set)) {
		err = -EBUSY;
		goto out;
	}

	krgnodes_or(exclusive_set, exclusive_set, s->node_set);
	s->node_set_exclusive = 1;

out:
	return err;
}

static void make_node_set_not_exclusive(struct scheduler *s)
{
	if (s->node_set_exclusive) {
		krgnodes_andnot(exclusive_set,
				exclusive_set,
				s->node_set);
		s->node_set_exclusive = 0;
	}
}

static
ssize_t
node_set_exclusive_store(struct scheduler *s, const char *page, size_t count)
{
	int new_state;
	char *last_read;
	int err;

	new_state = simple_strtoul(page, &last_read, 0);
	if (last_read - page + 1 < count
	    || (last_read[1] != '\0' && last_read[1] != '\n'))
		return -EINVAL;

	spin_lock(&schedulers_list_lock);
	if (new_state) {
		err = make_node_set_exclusive(s);
	} else {
		make_node_set_not_exclusive(s);
		err = 0;
	}
	spin_unlock(&schedulers_list_lock);

	return err ? err : count;
}

static struct scheduler_attribute node_set_exclusive = {
	.config = {
		.ca_name = "node_set_exclusive",
		.ca_owner = THIS_MODULE,
		.ca_mode = S_IRUGO | S_IWUSR,
	},
	.show = node_set_exclusive_show,
	.store = node_set_exclusive_store
};

static struct configfs_attribute *scheduler_attrs[] = {
	&node_set.config,
	&node_set_exclusive.config,
	NULL
};

/**
 * This struct is ConfigFS-specific. See ConfigFS documentation for its
 * explanation.
 */
static struct config_item_type scheduler_type = {
	.ct_owner = THIS_MODULE,
	.ct_item_ops = &scheduler_item_ops,
	.ct_group_ops = &scheduler_group_ops,
	.ct_attrs = scheduler_attrs
};

/**
 * Create a scheduler with no processes attached and no scheduling policy.
 *
 * @param name		Name of the directory containing the scheduler
 *
 * @return		pointer to the new scheduler, or
 *			NULL if error
 */
static struct scheduler *scheduler_create(const char *name)
{
	struct scheduler *s = kmalloc(sizeof(*s), GFP_KERNEL);

	if (!s)
		return NULL;
	memset(&s->group, 0, sizeof(s->group));
	config_group_init_type_name(&s->group, name, &scheduler_type);
	s->policy = NULL;
	s->processes = process_set_create();
	if (!s->processes) {
		config_group_put(&s->group);
		return NULL;
	}
	mutex_init(&s->node_set_mutex);
	s->node_set_exclusive = 0;
	s->default_groups[0] = &s->processes->group;
	s->default_groups[1] = NULL;
	s->group.default_groups = s->default_groups;
	spin_lock_init(&s->lock);
	return s;
}

/**
 * Free a scheduler
 */
static void scheduler_free(struct scheduler *scheduler)
{
	kfree(scheduler);
}

/* Global_config callback when the scheduler directory is globally removed */
static void scheduler_drop(struct global_config_item *item)
{
	struct scheduler *scheduler =
		container_of(item, struct scheduler, global_item);
	spin_lock(&schedulers_list_lock);
	list_del(&scheduler->list);
	make_node_set_not_exclusive(scheduler);
	spin_unlock(&schedulers_list_lock);
	config_group_put(&scheduler->group);
}

static struct global_config_drop_operations scheduler_drop_ops = {
	.drop_func = scheduler_drop,
	.is_symlink = 0
};

/*
 * Configfs callback called when a user creates a directory under "schedulers"
 * subsystem directory. This creates a new scheduler.
 */
static struct config_group *schedulers_make_group(struct config_group *group,
						  const char *name)
{
	struct config_group *ret;
	struct scheduler *s;
	struct string_list_object *global_names;
	int err;

	ret = ERR_PTR(-EPERM);
	if (!(current->flags & PF_KTHREAD) && !current->nsproxy->krg_ns)
		goto out;

	if (!IS_KERRIGHED_NODE(KRGFLAGS_RUNNING))
		goto out;

	global_names = global_config_make_item_begin(&group->cg_item, name);
	if (IS_ERR(global_names)) {
		ret = (void *)global_names;
		goto out;
	}

	err = -ENOMEM;
	s = scheduler_create(name);
	if (!s)
		goto err_scheduler;
	global_config_item_init(&s->global_item, &scheduler_drop_ops);
	err = __global_config_make_item_commit(global_names,
					       &group->cg_item,
					       &s->global_item,
					       name);
	if (err)
		goto err_global_end;
	spin_lock(&schedulers_list_lock);
	krgnodes_andnot(s->node_set, krgnode_online_map, exclusive_set);
	list_add(&s->list, &schedulers_head);
	spin_unlock(&schedulers_list_lock);
	__global_config_make_item_end(global_names);

	ret = &s->group;

out:
	return ret;

err_scheduler:
	global_config_make_item_error(global_names, name);
	ret = ERR_PTR(err);
	goto out;

err_global_end:
	__global_config_make_item_end(global_names);
	config_group_put(&s->group);
	ret = ERR_PTR(err);
	goto out;
}

static int schedulers_allow_drop_item(struct config_group *group,
				      struct config_item *item)
{
	if (!(current->flags & PF_KTHREAD) && !current->nsproxy->krg_ns)
		return -EPERM;
	return 0;
}

/* Configfs callback when a scheduler's directory is removed */
static void schedulers_drop_item(struct config_group *group,
				 struct config_item *item)
{
	struct scheduler *s = to_scheduler(item);
	spin_lock(&s->lock);
	process_set_drop(s->processes);
	s->processes = NULL;
	spin_unlock(&s->lock);
	global_config_drop(&s->global_item);
}

static struct configfs_group_operations schedulers_group_ops = {
	.make_group = schedulers_make_group,
	.allow_drop_item = schedulers_allow_drop_item,
	.drop_item = schedulers_drop_item,
};

static struct config_item_type schedulers_type = {
	.ct_owner = THIS_MODULE,
	.ct_group_ops = &schedulers_group_ops,
};

/**
 * This struct is ConfigFS-specific. See ConfigFS documentation for its
 * explanation.
 */
static struct config_group schedulers_group = {
	.cg_item = {
		.ci_namebuf = SCHEDULERS_NAME,
		.ci_type = &schedulers_type,
	},
};

/**
 * Initializes the "schedulers" subsystem directory.
 * @author Marko Novak, Louis Rilling
 */
struct config_group *scheduler_start(void)
{
	/* initialize configfs entry */
	config_group_init(&schedulers_group);
	return &schedulers_group;
}

void scheduler_exit(void)
{
	printk(KERN_WARNING "[%s] WARNING: loosing memory!\n",
	       __PRETTY_FUNCTION__);
}
