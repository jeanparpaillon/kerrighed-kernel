/*
 *  kerrighed/scheduler/process_set.c
 *
 *  Copyright (C) 2007 Marko Novak - Xlab
 *  Copyright (C) 2007-2008 Louis Rilling - Kerlabs
 */

#include <linux/kernel.h>
#include <linux/nsproxy.h>
#include <linux/pid.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/rculist.h>
#include <linux/mutex.h>
#include <linux/module.h>
#include <linux/err.h>
#include <kerrighed/pid.h>
#ifdef CONFIG_KRG_EPM
#include <kerrighed/ghost.h>
#include <kerrighed/action.h>
#endif
#include <kerrighed/scheduler/global_config.h>
#include <kerrighed/scheduler/process_set.h>

#include "internal.h"

static inline struct process_set *to_process_set(struct config_item *item)
{
	return container_of(to_config_group(item), struct process_set, group);
}

static
inline
struct process_subset *to_process_subset(struct config_item *item)
{
	return container_of(to_config_group(item),
			    struct process_subset, group);
}

static
inline
struct process_set_element *to_process_set_element(struct config_item *item)
{
	return container_of(item, struct process_set_element, item);
}

/**
 * Internal structure for representing process set attributes.
 */
struct pset_attribute {
	struct configfs_attribute attr;

	ssize_t (*show)(struct process_set *, char *);
	ssize_t (*store)(struct process_set *, const char *, size_t);
};

static
inline
struct pset_attribute *to_pset_attribute(struct configfs_attribute *attr)
{
	return container_of(attr, struct pset_attribute, attr);
}

static const char *process_subset_names[] = {
	[PIDTYPE_PID] = "single_processes",
	[PIDTYPE_PGID] = "process_groups",
	[PIDTYPE_SID] = "process_sessions"
};

LIST_HEAD(process_set_handle_all_head);
DEFINE_SPINLOCK(process_set_link_lock);

static void process_set_element_destroy(struct process_set_element *pset_el);

/* Configfs callback when ref count of a process_set_element reaches 0 */
static void process_set_element_release(struct config_item *item)
{
	struct process_set_element *pset_el = to_process_set_element(item);
	process_set_element_destroy(pset_el);
}

static struct configfs_item_operations process_element_item_ops = {
	.release = process_set_element_release,
};

static struct config_item_type process_element_type = {
        .ct_owner = THIS_MODULE,
	.ct_item_ops = &process_element_item_ops,
};

/**
 * Callback called by global_config when the element is globally dropped
 */
static void process_set_element_drop(struct global_config_item *item)
{
	struct process_set_element *pset_el =
		container_of(item, struct process_set_element, global_item);

	config_item_put(&pset_el->item);
}

static struct global_config_drop_operations process_set_element_drop_ops = {
	.drop_func = process_set_element_drop,
};

/**
 * Create a new process_set_element
 *
 * @param id		id of the new element
 *
 * @return		pointer to the new element, or
 *			NULL
 */
static struct process_set_element *process_set_element_new(pid_t id)
{
	struct process_set_element *pset_el = kmalloc(sizeof(*pset_el),
						      GFP_KERNEL);
	if (!pset_el)
		goto err_alloc;

	memset(pset_el, 0, sizeof(*pset_el));
	if (config_item_set_name(&pset_el->item, "%d", id))
		goto err_name;
	pset_el->item.ci_type = &process_element_type;
	config_item_init(&pset_el->item);
	pset_el->id = id;
	pset_el->pid = NULL;
	pset_el->in_subset = 0;
	global_config_item_init(&pset_el->global_item,
				&process_set_element_drop_ops);

	return pset_el;

err_name:
	kfree(pset_el);
err_alloc:
	return NULL;
}

/**
 * Free all memory allocated for a process_set_element
 *
 * @param pset_el	process_set_element to free
 */
static void process_set_element_destroy(struct process_set_element *pset_el)
{
	kfree(pset_el);
}

/**
 * Link a process_set_element to the local matching struct pid
 *
 * @param pset_el	process_set_element to link
 * @param pid		struct pid to link the process_set_element with
 * @param type		pid_type of the process_set_element
 */
static inline
void __process_set_element_link(struct process_set_element *pset_el,
				struct pid *pid, enum pid_type type)
{
	pset_el->pid = get_pid(pid);
	spin_lock(&process_set_link_lock);
	hlist_add_head_rcu(&pset_el->pid_node,
			   &pset_el->pid->process_sets[type]);
	spin_unlock(&process_set_link_lock);
}

/**
 * Link a process_set_element to the local matching struct pid, if it exists
 *
 * @param pset_el	process_set_element to link
 * @param type		pid_type of the process_set_element
 */
static inline void process_set_element_link(struct process_set_element *pset_el,
					    enum pid_type type)
{
	struct pid *pid;
	rcu_read_lock();
	pid = find_kpid(pset_el->id);
	if (pid)
		__process_set_element_link(pset_el, pid, type);
	rcu_read_unlock();
}

/**
 * Unlink a process_set_element from the local matching pid, if it exists
 *
 * @param pset_el	process_set_element to unlink
 */
static inline
void process_set_element_unlink(struct process_set_element *pset_el)
{
	if (pset_el->pid) {
		spin_lock(&process_set_link_lock);
		hlist_del_rcu(&pset_el->pid_node);
		spin_unlock(&process_set_link_lock);
		put_pid(pset_el->pid);
		pset_el->pid = NULL;
	}
}

/**
 * Checks whether a process_set_element is in a subset
 * WARNING: caller must handle race conditions with process_subset_add_element
 * and process_subset_remove_element
 *
 * @param pset_el	process_set_element to test
 *
 * @return		non 0 if process_set_element is an subset,
 *			0 otherwise
 */
static inline
int process_set_element_in_subset(struct process_set_element *pset_el)
{
	return pset_el->in_subset;
}

/**
 * Checks whether a process_set_element is linked to a pid
 * WARNING: caller must handle race conditions with process_set_element_link
 * and process_set_element_unlink
 *
 * @param pset_el	process_set_element to test
 *
 * @return		non 0 if process_set_element is linked to a pid,
 *			0 otherwise
 */
static inline
int process_set_element_linked(struct process_set_element *pset_el)
{
	return !!pset_el->pid;
}

static inline enum pid_type process_subset_type(struct process_subset *psubset)
{
	struct process_set *pset;
	pset = to_process_set(psubset->group.cg_item.ci_parent);
	return psubset - pset->subsets;
}

/**
 * Low-level function to add an element to a process subset
 *
 * @param psubset	subset to host the new element
 * @param pset_el	element to add the subset
 */
static inline
void process_subset_add_element(struct process_subset *psubset,
				struct process_set_element *pset_el)
{
	list_add_rcu(&pset_el->list, &psubset->elements_head);
	pset_el->in_subset = 1;
	process_set_element_link(pset_el, process_subset_type(psubset));
}

/**
 * Low-level function to remove an element from a process subset
 *
 * @param psubset	subset hosting the element to remove
 * @param pset_el	element to remove from the subset
 */
static inline
void process_subset_remove_element(struct process_subset *psubset,
				   struct process_set_element *pset_el)
{
	process_set_element_unlink(pset_el);
	pset_el->in_subset = 0;
	list_del_rcu(&pset_el->list);
}

/**
 * Check whether a process subset is empty
 *
 * @param psubset	subset to check
 *
 * @return		non 0 if psubset is empty,
 *			0 otherwise
 */
static inline int process_subset_empty(struct process_subset *psubset)
{
	return list_empty(&psubset->elements_head);
}

/**
 * Adds ID to a subset.
 */
static
struct config_item *process_subset_make_item(struct config_group *group,
					      const char *name)
{
	struct config_item *ret;
	struct process_set_element *pset_el;
	struct process_set *pset = to_process_set(group->cg_item.ci_parent);
	struct process_subset *psubset = to_process_subset(&group->cg_item);
	struct string_list_object *global_ids;
	pid_t id;
	int err;

	err = -EPERM;
	if (!(current->flags & PF_KTHREAD) && !current->nsproxy->krg_ns)
		goto err;

	global_ids = global_config_make_item_begin(&group->cg_item, name);
	if (IS_ERR(global_ids)) {
		err = PTR_ERR(global_ids);
		goto err;
	}

	/* convert string to PID number */
	/* TODO: ensure that name is exactly an integer */
	err = -EINVAL;
	if (sscanf(name, "%d", &id) != 1)
		goto err_id;

	err = -ENOMEM;
	pset_el = process_set_element_new(id);
	if (!pset_el)
		goto err_pset_el;

	/* add ID to the list */
	/*
	 * if particular scheduler already handles all the processes, there is
	 * no use in adding IDs to the list.
	 */
	err = -EPERM;
	process_set_lock(pset);
	if (process_set_contains_all(pset)) {
		process_set_unlock(pset);
		goto err_handle_all;
	}
	process_subset_add_element(psubset, pset_el);
	process_set_unlock(pset);

	err = global_config_make_item_end(global_ids,
					  &group->cg_item,
					  &pset_el->global_item,
					  config_item_name(&pset_el->item));
	if (err) {
		/*
		 * TODO: may make handle_all setting fail even if it succeeded
		 * on another node
		 */
		process_set_lock(pset);
		process_subset_remove_element(psubset, pset_el);
		process_set_unlock(pset);
		synchronize_rcu();
		config_item_put(&pset_el->item);
		goto err;
	}

	ret = &pset_el->item;

	return ret;

err_handle_all:
	config_item_put(&pset_el->item);
err_pset_el:
err_id:
	global_config_make_item_error(global_ids, name);
err:
	return ERR_PTR(err);
}

static int process_subset_allow_drop_item(struct config_group *group,
					  struct config_item *item)
{
	if (!(current->flags & PF_KTHREAD) && !current->nsproxy->krg_ns)
		return -EPERM;
	return 0;
}

/**
 * Removes ID from a subset.
 */
static void process_subset_drop_item(struct config_group *group,
				     struct config_item *item)
{
	struct process_subset *psubset = to_process_subset(&group->cg_item);
	struct process_set *pset = to_process_set(group->cg_item.ci_parent);
	struct process_set_element *pset_el = to_process_set_element(item);

	process_set_lock(pset);
	process_subset_remove_element(psubset, pset_el);
	process_set_unlock(pset);
	synchronize_rcu();

	global_config_drop(&pset_el->global_item);
}

static struct configfs_group_operations process_subset_group_ops = {
	.make_item = process_subset_make_item,
	.allow_drop_item = process_subset_allow_drop_item,
	.drop_item = process_subset_drop_item,
};

static struct config_item_type process_subset_item_type = {
	.ct_owner = THIS_MODULE,
	.ct_group_ops = &process_subset_group_ops,
};

/**
 * Initialize a process_subset
 *
 * @param psubset	process_subset to initialize
 * @param name		directory name of the subset
 */
static void process_subset_init(struct process_subset *psubset,
				const char *name)
{
	memset(&psubset->group, 0, sizeof(psubset->group));
	config_group_init_type_name(&psubset->group,
				    name, &process_subset_item_type);
	INIT_LIST_HEAD(&psubset->elements_head);
}

/**
 * Cleanup a process_subset
 * Must be called before freeing the object containing the subset
 *
 * @param psubset	process_subset to cleanup
 */
static void process_subset_cleanup(struct process_subset *psubset)
{
	config_group_put(&psubset->group);
}

/**
 * Shows value of "handle_all" attribute.
 */
static ssize_t pset_handle_all_show(struct process_set *pset, char *page)
{
	ssize_t ret;
	/*
	 * We do not really care about locking here, since things may change
	 * before userspace gets the result anyway.
	 */
	ret = sprintf(page, "%d\n", process_set_contains_all(pset));
	return ret;
}

/**
 * Stores value of "handle_all" attribute.
 */
static ssize_t pset_handle_all_store(struct process_set *pset,
				     const char *page, size_t count)
{
	short int val;
	enum pid_type type;
	ssize_t ret;

	process_set_lock(pset);

	/*
	 * Do not accept to handle all processes as long as specific ones live
	 * in the set
	 */
	for (type = 0; type < PIDTYPE_MAX; type++)
		if (!process_subset_empty(&pset->subsets[type])) {
			ret = -EPERM;
			goto out;
		}

	if (sscanf(page, "%hd", &val) != 1) {
		ret = -EINVAL;
	} else {
		spin_lock(&process_set_link_lock);
		if (val <= 0 && process_set_contains_all(pset)) {
			/*
			 * if user inserted 0 or negative number, corresponding
			 * scheduler doesn't handle all processes.
			 */
			pset->handle_all = 0;
			list_del_rcu(&pset->handle_all_list);
		} else if (val > 0 && !process_set_contains_all(pset)) {
			/*
			 * if user inserted positive number, corresponding
			 * scheduler handles all processes.
			 */
			list_add_rcu(&pset->handle_all_list,
				     &process_set_handle_all_head);
			pset->handle_all = 1;
		}
		spin_unlock(&process_set_link_lock);
		ret = count;
	}

out:
	process_set_unlock(pset);
	/*
	 * Be sure to not re-add pset to the handle all list before concurrent
	 * list traversals end
	 */
	synchronize_rcu();
	return ret;
}

/**
 * The "handle_all" attribute determines if particular set contains all
 * processes.
 */
static struct pset_attribute pset_handle_all = {
	.attr = {
		.ca_name = "handle_all",
		.ca_owner = THIS_MODULE,
		.ca_mode = S_IRUGO | S_IWUSR,
	},
	.show = pset_handle_all_show,
	.store = pset_handle_all_store,
};

static struct configfs_attribute *pset_attributes[] = {
	&pset_handle_all.attr,
	NULL,
};

/**
 * This is general function for showing values of process set attributes.
 */
static ssize_t pset_attribute_show(struct config_item *item,
				   struct configfs_attribute *attr,
				   char *page)
{
	struct pset_attribute *pset_attr = to_pset_attribute(attr);
	struct process_set *pset = to_process_set(item);
	ssize_t ret = 0;

	if (pset_attr->show)
		ret = pset_attr->show(pset, page);

	return ret;
}

/**
 * This is general function for storing values of process set attributes.
 */
static ssize_t pset_attribute_store(struct config_item *item,
				    struct configfs_attribute *attr,
				    const char *page, size_t count)
{
	struct pset_attribute *pset_attr = to_pset_attribute(attr);
	struct process_set *pset = to_process_set(item);
	ssize_t ret = 0;

	if (!(current->flags & PF_KTHREAD) && !current->nsproxy->krg_ns)
		return -EPERM;

	if (pset_attr->store) {
		struct string_list_object *list;

		list = global_config_attr_store_begin(item);
		if (IS_ERR(list))
			return PTR_ERR(list);

		ret = pset_attr->store(pset, page, count);

		if (ret >= 0)
			ret = global_config_attr_store_end(list,
							   item, attr,
							   page, ret);
		else
			global_config_attr_store_error(list, item);
	}

	return ret;
}

static void process_set_release(struct config_item *item);

static
struct global_config_attrs *process_set_global_attrs(struct config_item *item)
{
	return &to_process_set(item)->global_attrs;
}

struct global_config_item_operations process_set_global_item_ops = {
	.config = {
		.release = process_set_release,
		.show_attribute = pset_attribute_show,
		.store_attribute = pset_attribute_store,
	},
	.global_attrs = process_set_global_attrs,
};

static struct config_item_type pset_type = {
        .ct_owner = THIS_MODULE,
	.ct_item_ops = &process_set_global_item_ops.config,
	.ct_attrs = pset_attributes,
};

/**
 * This function allocates memory for new process set and initializes it.
 * Note: at the beginning the process set doesn't contain any processes nor
 * process groups.
 * @author Marko Novak, Louis Rilling
 *
 * @return              pointer to newly created process set or NULL if
 *                      creation failed.
 */
struct process_set *process_set_create(void)
{
	struct process_set *pset;
	enum pid_type type;

	pset = kmalloc(sizeof(struct process_set), GFP_KERNEL);
	if (!pset)
		goto err_kmalloc;

	/* initialize process set. */
	memset(&pset->group, 0, sizeof(pset->group));
	config_group_init_type_name(&pset->group, "process_set", &pset_type);
	for (type = 0; type < PIDTYPE_MAX; type++) {
		process_subset_init(&pset->subsets[type],
				    process_subset_names[type]);
		pset->def_groups[type] = &pset->subsets[type].group;
	}
	pset->def_groups[PIDTYPE_MAX] = NULL;
	pset->group.default_groups = pset->def_groups;

	/*
	 * by default, particular scheduling policy doesn't handle any
	 * process.
	 */
	pset->handle_all = 0;

	spin_lock_init(&pset->lock);

	return pset;

err_kmalloc:
	return NULL;
}

static void delayed_process_set_put(struct rcu_head *rcu)
{
	struct process_set *pset = container_of(rcu, struct process_set, rcu);
	process_set_put(pset);
}

void process_set_drop(struct process_set *pset)
{
	process_set_lock(pset);
	if (pset->handle_all) {
		pset->handle_all = 0;
		spin_lock(&process_set_link_lock);
		list_del_rcu(&pset->handle_all_list);
		spin_unlock(&process_set_link_lock);
	}
	process_set_unlock(pset);
	call_rcu(&pset->rcu, delayed_process_set_put);
}

/**
 * ConfigFS callback when the last reference on a process set is dropped
 * Frees all the memory allocated for a process set
 */
static void process_set_release(struct config_item *item)
{
	struct process_set *pset = to_process_set(item);
	enum pid_type type;
	for (type = 0; type < PIDTYPE_MAX; type++)
		process_subset_cleanup(&pset->subsets[type]);
	kfree(pset);
}

#ifdef CONFIG_KRG_EPM

/*
 * Ghost export / import functions
 *
 * The exporting procedure to follow is:
 * - call export_process_set_links_start
 * - call export_process_set_links for each desired pid_type
 * - call export_process_set_links_end
 */

int export_process_set_links_start(struct epm_action *action, ghost_t *ghost,
				   struct task_struct *task)
{
	if (action->type != EPM_MIGRATE && action->type != EPM_REMOTE_CLONE)
		return 0;
	return global_config_freeze();
}

int export_process_set_links(struct epm_action *action, ghost_t *ghost,
			     struct pid *pid, enum pid_type type)
{
	struct process_set_element **elements;
	struct process_set_element *pset_el;
	struct hlist_node *pos;
	int nr_links, nr;
	int err;

	if (action->type != EPM_MIGRATE && action->type != EPM_REMOTE_CLONE)
		return 0;

	/*
	 * process_set_elements found in pid->process_set_links will remain
	 * linked until we release the subsystem mutex, since all
	 * link/unlink are done in make_item/drop_item operations or in
	 * import_process_set_links with the mutex held.
	 */
	mutex_lock(&krg_scheduler_subsys.su_mutex);

	nr_links = 0;
	/*
	 * No need to acquire process_set_link_lock since all mutations of
	 * process set links are protected by krg_scheduler_subsys.su_mutex
	 */
	hlist_for_each(pos, &pid->process_sets[type])
		nr_links++;

	err = -ENOMEM;
	elements = kmalloc(sizeof(*elements) * nr_links, GFP_KERNEL);
	if (!elements)
		goto out_unlock;

	nr = 0;
	/*
	 * Traverse the list in reverse order so that import restores the list
	 * in the same order as the one of this node
	 */
	if (nr_links) {
		struct hlist_head *head = &pid->process_sets[type];
		struct hlist_node **pnext;

		/* The list has at least one element. */
		/* Find the last element */
		for (pos = head->first; pos->next; pos = pos->next);
		/* Start from last element and stop when head is reached */
		for (pnext = &pos->next;
		     pnext != &head->first &&
			     ({ pos = container_of(pnext, struct hlist_node, next); 1; });
		     pnext = pos->pprev) {
			pset_el = hlist_entry(pos,
					      struct process_set_element, pid_node);
			elements[nr++] = pset_el;
		}
	}
	BUG_ON(nr != nr_links);

	err = ghost_write(ghost, &nr_links, sizeof(nr_links));
	if (err)
		goto out_free;

	for (nr = 0; nr < nr_links; nr++) {
		/* Export the globalized process_set_element */
		err = export_global_config_item(action, ghost,
						&elements[nr]->item);
		if (err)
			break;
	}

out_free:
	kfree(elements);
out_unlock:
	mutex_unlock(&krg_scheduler_subsys.su_mutex);

	return err;
}

void export_process_set_links_end(struct epm_action *action, ghost_t *ghost,
				  struct task_struct *task)
{
	if (action->type == EPM_MIGRATE || action->type == EPM_REMOTE_CLONE)
		global_config_thaw();
}

int import_process_set_links(struct epm_action *action, ghost_t *ghost,
			     struct pid *pid, enum pid_type type)
{
	struct process_set_element *pset_el;
	struct config_item *item;
	int nr_links, nr;
	int err;

	if (action->type != EPM_MIGRATE && action->type != EPM_REMOTE_CLONE)
		return 0;

	err = ghost_read(ghost, &nr_links, sizeof(nr_links));
	if (err)
		goto out;

	for (nr = 0; nr < nr_links; nr++) {
		err = import_global_config_item(action, ghost, &item);
		if (err)
			break;
		/*
		 * Some imported process_set_element may not exist anymore, so
		 * do not make import fail in that case.
		 */
		if (IS_ERR(item))
			continue;

		pset_el = to_process_set_element(item);
		/*
		 * Taking the subsystem mutex blocks all other calls of
		 * __process_set_element_link and process_set_element_unlink
		 */
		mutex_lock(&krg_scheduler_subsys.su_mutex);
		/*
		 * item must not be added to a pid list of links unless it is
		 * still linked in configfs.
		 */
		/*
		 * Note: here we may race with a process set traversal, even if
		 * it acquired the process set lock before. We can live with
		 * this since the incoming task may be considered as not
		 * completely there yet.
		 */
		if (process_set_element_in_subset(pset_el)
		    && !process_set_element_linked(pset_el))
			__process_set_element_link(pset_el, pid, type);
		mutex_unlock(&krg_scheduler_subsys.su_mutex);

		config_item_put(item);
	}

out:
	return err;
}

#endif /* CONFIG_KRG_EPM */
