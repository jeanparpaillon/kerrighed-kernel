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
#include <kerrighed/hotplug.h>
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
	struct global_config_attrs global_attrs;

	krgnodemask_t node_set;
	unsigned node_set_exclusive:1;
	unsigned node_set_max_fit:1;

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
static DEFINE_MUTEX(schedulers_list_mutex);

static krgnodemask_t shared_set;

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

static inline const krgnodemask_t *get_node_set(struct scheduler *scheduler)
{
	if (scheduler->node_set_max_fit) {
		if (scheduler->node_set_exclusive)
			return &krgnode_online_map;
		else
			return &shared_set;
	} else {
		return &scheduler->node_set;
	}
}

static
inline void set_node_set(struct scheduler *scheduler, const krgnodemask_t *set)
{
	BUG_ON(scheduler->node_set_max_fit);
	__krgnodes_copy(&scheduler->node_set, set);
}

void scheduler_get_node_set(struct scheduler *scheduler,
			    krgnodemask_t *node_set)
{
	spin_lock(&schedulers_list_lock);
	spin_lock(&scheduler->lock);
	__krgnodes_copy(node_set, get_node_set(scheduler));
	spin_unlock(&scheduler->lock);
	spin_unlock(&schedulers_list_lock);
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

static
struct global_config_attrs *scheduler_global_attrs(struct config_item *item)
{
	return &to_scheduler(item)->global_attrs;
}

struct global_config_item_operations scheduler_global_item_ops = {
	.config = {
		.show_attribute = scheduler_show_attribute,
		.store_attribute = scheduler_store_attribute,
		.release = scheduler_release,
	},
	.global_attrs = scheduler_global_attrs,
};

/**
 * Callback called by global_config when the scheduler_policy of a scheduler is
 * globally dropped
 */
static void policy_global_drop(struct global_config_item *item)
{
	struct scheduler_policy *policy =
		container_of(item, struct scheduler_policy, global_item);
	global_config_attrs_cleanup_r(&policy->group);
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
	global_config_attrs_init_r(&policy->group);
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
	global_config_attrs_cleanup_r(&policy->group);
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
	krgnodemask_t set;

	scheduler_get_node_set(s, &set);
	return krgnodelist_scnprintf(page, SCHEDULER_ATTR_SIZE, set);
}

static int node_set_may_be_exclusive(const struct scheduler *s,
				     const krgnodemask_t *node_set);

static void policy_update_node_set(struct scheduler *scheduler,
				   const krgnodemask_t *removed_set,
				   const krgnodemask_t *added_set)
{
	struct scheduler_policy *policy;

	policy = scheduler_get_scheduler_policy(scheduler);
	if (policy) {
		scheduler_policy_update_node_set(policy,
						 get_node_set(scheduler),
						 removed_set,
						 added_set);
		scheduler_policy_put(policy);
	}
}

static int __do_update_node_set(struct scheduler *s,
			        const krgnodemask_t *new_set,
			        bool max_fit)
{
	krgnodemask_t removed_set, added_set;
	const krgnodemask_t *old_set;
	struct scheduler_policy *policy = NULL;
	int err = -EBUSY;

	spin_lock(&schedulers_list_lock);

	if (max_fit) {
		if (s->node_set_exclusive)
			new_set = &krgnode_online_map;
		else
			new_set = &shared_set;
	} else if (!new_set) {
		new_set = get_node_set(s);
	}

	old_set = get_node_set(s);
	krgnodes_andnot(removed_set, *old_set, *new_set);
	krgnodes_andnot(added_set, *new_set, *old_set);

	if (s->node_set_exclusive) {
		if (!node_set_may_be_exclusive(s, new_set))
			goto unlock;
		krgnodes_andnot(shared_set, shared_set, added_set);
		krgnodes_or(shared_set, shared_set, removed_set);
	} else {
		if (!krgnodes_subset(*new_set, shared_set))
			goto unlock;
	}
	err = 0;

	spin_lock(&s->lock);
	s->node_set_max_fit = max_fit;
	if (!max_fit)
		set_node_set(s, new_set);
	policy = s->policy;
	scheduler_policy_get(policy);
	spin_unlock(&s->lock);
unlock:
	spin_unlock(&schedulers_list_lock);

	if (!err)
		policy_update_node_set(s, &removed_set, &added_set);

	return err;
}

static int do_update_node_set(struct scheduler *s,
			      const krgnodemask_t *new_set,
			      bool max_fit)
{
	int err;

	mutex_lock(&schedulers_list_mutex);
	err = __do_update_node_set(s, new_set, max_fit);
	mutex_unlock(&schedulers_list_mutex);

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
			err = do_update_node_set(s, &new_set, false);
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
	return sprintf(page, "%u", s->node_set_exclusive);
}

static int node_set_may_be_exclusive(const struct scheduler *s,
			    const krgnodemask_t *node_set)
{
	struct scheduler *pos;

	list_for_each_entry(pos, &schedulers_head, list)
		if (pos != s
		    && (pos->node_set_exclusive || !pos->node_set_max_fit)
		    && krgnodes_intersects(*node_set, *get_node_set(pos)))
			return 0;
	return 1;
}

static int make_node_set_exclusive(struct scheduler *s)
{
	const krgnodemask_t *set = get_node_set(s);
	int err = 0;

	if (s->node_set_exclusive)
		goto out;

	if (!node_set_may_be_exclusive(s, set)) {
		err = -EBUSY;
		goto out;
	}

	krgnodes_andnot(shared_set, shared_set, *set);
	s->node_set_exclusive = 1;

out:
	return err;
}

static void make_node_set_not_exclusive(struct scheduler *s)
{
	if (s->node_set_exclusive) {
		krgnodes_or(shared_set, shared_set, *get_node_set(s));
		s->node_set_exclusive = 0;
	}
}

static
ssize_t
node_set_exclusive_store(struct scheduler *s, const char *page, size_t count)
{
	int new_state;
	char *last_read;
	krgnodemask_t added, removed;
	bool changed;
	int err;

	new_state = simple_strtoul(page, &last_read, 0);
	if (last_read - page + 1 < count
	    || (last_read[1] != '\0' && last_read[1] != '\n'))
		return -EINVAL;

	mutex_lock(&schedulers_list_mutex);
	spin_lock(&schedulers_list_lock);
	if (new_state) {
		krgnodes_clear(added);
		krgnodes_copy(removed, *get_node_set(s));
		changed = !s->node_set_exclusive;
		err = make_node_set_exclusive(s);
		changed = changed && !err;
	} else {
		krgnodes_copy(added, *get_node_set(s));
		krgnodes_clear(removed);
		changed = s->node_set_exclusive;
		make_node_set_not_exclusive(s);
		err = 0;
	}
	spin_unlock(&schedulers_list_lock);

	if (changed) {
		list_for_each_entry(s, &schedulers_head, list)
			if (s->node_set_max_fit)
				policy_update_node_set(s, &removed, &added);
	}
	mutex_unlock(&schedulers_list_mutex);

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

static ssize_t node_set_max_fit_show(struct scheduler *s, char *page)
{
	return sprintf(page, "%u", s->node_set_max_fit);
}

static
ssize_t
node_set_max_fit_store(struct scheduler *s, const char *page, size_t count)
{
	int new_state;
	char *last_read;
	int err;

	new_state = simple_strtoul(page, &last_read, 0);
	if (last_read - page + 1 < count
	    || (last_read[1] != '\0' && last_read[1] != '\n'))
		return -EINVAL;

	err = do_update_node_set(s, NULL, new_state);
	return err ? err : count;
}

static struct scheduler_attribute node_set_max_fit = {
	.config = {
		.ca_name = "node_set_max_fit",
		.ca_owner = THIS_MODULE,
		.ca_mode = S_IRUGO | S_IWUSR,
	},
	.show = node_set_max_fit_show,
	.store = node_set_max_fit_store
};

static struct configfs_attribute *scheduler_attrs[] = {
	&node_set.config,
	&node_set_exclusive.config,
	&node_set_max_fit.config,
	NULL
};

/**
 * This struct is ConfigFS-specific. See ConfigFS documentation for its
 * explanation.
 */
static struct config_item_type scheduler_type = {
	.ct_owner = THIS_MODULE,
	.ct_item_ops = &scheduler_global_item_ops.config,
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
	s->node_set_exclusive = 0;
	s->node_set_max_fit = 1;
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

static void scheduler_deactivate(struct scheduler *scheduler)
{
	spin_lock(&scheduler->lock);
	process_set_drop(scheduler->processes);
	scheduler->processes = NULL;
	spin_unlock(&scheduler->lock);
}

/* Global_config callback when the scheduler directory is globally removed */
static void scheduler_drop(struct global_config_item *item)
{
	struct scheduler *scheduler =
		container_of(item, struct scheduler, global_item);

	global_config_attrs_cleanup_r(&scheduler->group);

	mutex_lock(&schedulers_list_mutex);
	spin_lock(&schedulers_list_lock);
	list_del(&scheduler->list);
	make_node_set_not_exclusive(scheduler);
	spin_unlock(&schedulers_list_lock);
	mutex_unlock(&schedulers_list_mutex);

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

	if (!(current->flags & PF_KTHREAD)
	    && !IS_KERRIGHED_NODE(KRGFLAGS_RUNNING))
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
	global_config_attrs_init_r(&s->group);
	global_config_item_init(&s->global_item, &scheduler_drop_ops);
	err = __global_config_make_item_commit(global_names,
					       &group->cg_item,
					       &s->global_item,
					       name);
	if (err)
		goto err_global_end;
	mutex_lock(&schedulers_list_mutex);
	spin_lock(&schedulers_list_lock);
	list_add(&s->list, &schedulers_head);
	spin_unlock(&schedulers_list_lock);
	mutex_unlock(&schedulers_list_mutex);
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
	global_config_attrs_cleanup_r(&s->group);
	scheduler_deactivate(s);
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

	scheduler_deactivate(s);
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

int scheduler_post_add(struct hotplug_context *ctx)
{
	const krgnodemask_t *added = &ctx->node_set.v;
	krgnodemask_t removed = KRGNODE_MASK_NONE;
	struct scheduler *s;

	mutex_lock(&schedulers_list_mutex);

	list_for_each_entry(s, &schedulers_head, list)
		if (s->node_set_exclusive && s->node_set_max_fit) {
			policy_update_node_set(s, &removed, added);
			goto unlock;
		}

	spin_lock(&schedulers_list_lock);
	krgnodes_or(shared_set, shared_set, *added);
	spin_unlock(&schedulers_list_lock);

	list_for_each_entry(s, &schedulers_head, list)
		if (s->node_set_max_fit)
			policy_update_node_set(s, &removed, added);

unlock:
	mutex_unlock(&schedulers_list_mutex);

	return 0;
}

int scheduler_remove(struct hotplug_context *ctx)
{
	krgnodemask_t added = KRGNODE_MASK_NONE;
	const krgnodemask_t *removed = &ctx->node_set.v;
	struct scheduler *s;
	krgnodemask_t set;

	mutex_lock(&schedulers_list_mutex);

	spin_lock(&schedulers_list_lock);
	krgnodes_andnot(shared_set, shared_set, ctx->node_set.v);
	spin_unlock(&schedulers_list_lock);

	list_for_each_entry(s, &schedulers_head, list) {
		if (s->node_set_max_fit) {
			policy_update_node_set(s, removed, &added);
		} else {
			krgnodes_andnot(set, s->node_set, *removed);
			__do_update_node_set(s, &set, false);
		}
	}

	mutex_unlock(&schedulers_list_mutex);

	return 0;
}

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
