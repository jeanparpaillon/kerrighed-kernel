/*
 *  kerrighed/epm/children.c
 *
 *  Copyright (C) 2006-2007 Louis Rilling - Kerlabs
 */

#include <linux/types.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/pid_namespace.h>
#include <linux/list.h>
#include <linux/kernel.h>
#include <linux/rwsem.h>
#include <linux/kref.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/hashtable.h>
#include <kerrighed/children.h>
#include <kerrighed/task.h>
#include <kerrighed/pid.h>
#include <kerrighed/krginit.h>
#include <net/krgrpc/rpc.h>
#include <kddm/kddm.h>
#include <kerrighed/krg_exit.h>	/* For remote zombies handling */
#include <kerrighed/libproc.h>

struct remote_child {
	struct list_head sibling;
	struct list_head thread_group;
	pid_t pid;
	pid_t tgid;
	pid_t pgid;
	pid_t sid;
	pid_t parent;
	pid_t real_parent;
	int ptraced;
	int exit_signal;
	long exit_state;
	kerrighed_node_t node;
};

struct children_kddm_object {
	pid_t tgid;
	struct list_head children;
	unsigned long nr_children;
	unsigned long nr_threads;
	u32 self_exec_id;

	/* Remaining fields are not shared */
	struct rw_semaphore sem;
	int write_locked;

	int alive;
	struct kref kref;

	struct rcu_head rcu;
};

static struct kmem_cache *children_obj_cachep;
static struct kmem_cache *remote_child_cachep;
struct kddm_set;
static struct kddm_set *children_kddm_set;

static struct kmem_cache *krg_parent_head_cachep;
/* Size of krg_parent task struct list hash table */
#define PROCESS_HASH_TABLE_SIZE 1024
static hashtable_t *krg_parent_table; /* list_head of local children */

/************************************************************************
 * Global children list of a thread group				*
 ************************************************************************/

void krg_children_get(struct children_kddm_object *obj)
{
	if (obj)
		kref_get(&obj->kref);
}

static void children_free(struct children_kddm_object *obj)
{
	struct remote_child *child, *next;

	list_for_each_entry_safe(child, next, &obj->children, sibling) {
		list_del(&child->sibling);
		kmem_cache_free(remote_child_cachep, child);
	}
	kmem_cache_free(children_obj_cachep, obj);
}

static void delayed_children_free(struct rcu_head *rhp)
{
	struct children_kddm_object *obj =
		container_of(rhp, struct children_kddm_object, rcu);
	children_free(obj);
}

static void children_free_rcu(struct kref *kref)
{
	struct children_kddm_object *obj =
		container_of(kref, struct children_kddm_object, kref);
	call_rcu(&obj->rcu, delayed_children_free);
}

void krg_children_put(struct children_kddm_object *obj)
{
	if (obj)
		kref_put(&obj->kref, children_free_rcu);
}

static inline void remove_child_links(struct children_kddm_object *obj,
				      struct remote_child *child)
{
	list_del(&child->sibling);
	list_del(&child->thread_group);
}

static void set_child_links(struct children_kddm_object *obj,
			    struct remote_child *child)
{
	struct remote_child *item;

	INIT_LIST_HEAD(&child->thread_group);
	if (child->pid != child->tgid) {
		list_for_each_entry(item, &obj->children, sibling)
			if (item->tgid == child->tgid) {
				list_add_tail(&child->thread_group,
					      &item->thread_group);
				break;
			}
		BUG_ON(list_empty(&child->thread_group));
	}
	list_add_tail(&child->sibling, &obj->children);
}

static int children_alloc_object(struct kddm_obj *obj_entry,
				 struct kddm_set *set, objid_t objid)
{
	struct children_kddm_object *obj;
	pid_t tgid = objid;

	obj = kmem_cache_alloc(children_obj_cachep, GFP_KERNEL);
	if (!obj)
		return -ENOMEM;

	obj->tgid = tgid;
	INIT_LIST_HEAD(&obj->children);
	obj->nr_children = 0;
	obj->nr_threads = 0;
	obj->self_exec_id = 0;
	init_rwsem(&obj->sem);
	obj->alive = 1;
	kref_init(&obj->kref);
	obj_entry->object = obj;

	return 0;
}

static int children_first_touch(struct kddm_obj *obj_entry,
				struct kddm_set *set, objid_t objid,int flags)
{
	return children_alloc_object(obj_entry, set, objid);
}

static int children_export_object(struct rpc_desc *desc,
				  struct kddm_set *set,
				  struct kddm_obj *obj_entry,
				  objid_t objid)
{
	struct children_kddm_object *obj = obj_entry->object;
	struct remote_child *child;
	int retval = 0;

	BUG_ON(!obj);
	BUG_ON(!(obj->tgid & GLOBAL_PID_MASK));

	retval = rpc_pack_type(desc, obj->nr_children);
	if (unlikely(retval))
		goto out;
	retval = rpc_pack_type(desc, obj->nr_threads);
	if (unlikely(retval))
		goto out;
	retval = rpc_pack_type(desc, obj->self_exec_id);
	if (unlikely(retval))
		goto out;
	list_for_each_entry(child, &obj->children, sibling) {
		retval = rpc_pack_type(desc, *child);
		if (unlikely(retval))
			goto out;
	}

out:
	return retval;
}

static int children_import_object(struct rpc_desc *desc,
				  struct kddm_set *set,
				  struct kddm_obj *obj_entry,
				  objid_t objid)
{
	struct children_kddm_object *obj = obj_entry->object;
	struct remote_child *child, *next;
	typeof(obj->nr_children) nr_children;
	typeof(obj->nr_children) min_children;
	typeof(min_children) i;
	LIST_HEAD(children_head);
	int retval = 0;

	BUG_ON(!obj);
	BUG_ON(!(obj->tgid & GLOBAL_PID_MASK));

	retval = rpc_unpack_type(desc, nr_children);
	if (unlikely(retval))
		goto out;
	retval = rpc_unpack_type(desc, obj->nr_threads);
	if (unlikely(retval))
		goto out;
	retval = rpc_unpack_type(desc, obj->self_exec_id);
	if (unlikely(retval))
		goto out;

	min_children = min(nr_children, obj->nr_children);

	/* Reuse allocated elements as much as possible */

	/* First, delete elements that won't be used anymore */
	i = 0;
	list_for_each_entry_safe(child, next, &obj->children, sibling) {
		if (i + min_children == obj->nr_children)
			break;
		remove_child_links(obj, child);
		kmem_cache_free(remote_child_cachep, child);
		i++;
	}
	BUG_ON(i + min_children != obj->nr_children);

	/* Second, fill in already allocated elements */
	i = 0;
	list_splice_init(&obj->children, &children_head);
	list_for_each_entry_safe(child, next, &children_head, sibling) {
		/* Does not need that child be linked to the obj->children
		 * list, but only to a list */
		remove_child_links(obj, child);
		retval = rpc_unpack_type(desc, *child);
		if (unlikely(retval))
			goto err_free_child;
		/* Put the child to the obj->children list */
		set_child_links(obj, child);
		i++;
	}
	BUG_ON(i != min_children);

	/* Third, allocate, fill in, and add remaininig elements to import */
	for (; i < nr_children; i++) {
		child = kmem_cache_alloc(remote_child_cachep, GFP_KERNEL);
		if (unlikely(!child)) {
			retval = -ENOMEM;
			goto out;
		}
		retval = rpc_unpack_type(desc, *child);
		if (unlikely(retval))
			goto err_free_child;
		set_child_links(obj, child);
	}
	BUG_ON(i != nr_children);

	obj->nr_children = nr_children;

out:
	return retval;

err_free_child:
	kmem_cache_free(remote_child_cachep, child);
	goto out;
}

static int children_remove_object(void *object, struct kddm_set *set,
				  objid_t objid)
{
	struct children_kddm_object *obj;

	obj = object;
	BUG_ON(!obj);

	obj->alive = 0;
	krg_children_put(obj);

	return 0;
}

static struct iolinker_struct children_io_linker = {
	.linker_name   = "children ",
	.linker_id     = CHILDREN_LINKER,
	.alloc_object  = children_alloc_object,
	.first_touch   = children_first_touch,
	.export_object = children_export_object,
	.import_object = children_import_object,
	.remove_object = children_remove_object,
	.default_owner = global_pid_default_owner,
};

struct children_kddm_object *krg_children_readlock(pid_t tgid)
{
	struct children_kddm_object *obj;

	/* Filter well known cases of no children kddm object. */
	if (!(tgid & GLOBAL_PID_MASK))
		return NULL;

	obj = _kddm_get_object_no_ft(children_kddm_set, tgid);
	if (obj) {
		down_read(&obj->sem);
		/* Marker for unlock. Dirty but temporary. */
		obj->write_locked = 0;
	} else {
		_kddm_put_object(children_kddm_set, tgid);
	}

	return obj;
}

struct children_kddm_object *__krg_children_readlock(struct task_struct *task)
{
	return krg_children_readlock(task_tgid_knr(task));
}

static struct children_kddm_object *children_writelock(pid_t tgid, int nested)
{
	struct children_kddm_object *obj;

	/* Filter well known cases of no children kddm object. */
	if (!(tgid & GLOBAL_PID_MASK))
		return NULL;

	obj = _kddm_grab_object_no_ft(children_kddm_set, tgid);
	if (obj) {
		if (!nested)
			down_write(&obj->sem);
		else
			down_write_nested(&obj->sem, SINGLE_DEPTH_NESTING);
		/* Marker for unlock. Dirty but temporary. */
		obj->write_locked = 1;
	} else {
		_kddm_put_object(children_kddm_set, tgid);
	}

	return obj;
}

struct children_kddm_object *krg_children_writelock(pid_t tgid)
{
	return children_writelock(tgid, 0);
}

struct children_kddm_object *__krg_children_writelock(struct task_struct *task)
{
	return children_writelock(task_tgid_knr(task), 0);
}

struct children_kddm_object *krg_children_writelock_nested(pid_t tgid)
{
	return children_writelock(tgid, 1);
}

static struct children_kddm_object *children_create_writelock(pid_t tgid)
{
	struct children_kddm_object *obj;

	BUG_ON(!(tgid & GLOBAL_PID_MASK));

	obj = _kddm_grab_object(children_kddm_set, tgid);
	if (obj) {
		down_write(&obj->sem);
		/* Marker for unlock. Dirty but temporary. */
		obj->write_locked = 1;
	} else {
		_kddm_put_object(children_kddm_set, tgid);
	}

	return obj;
}

void krg_children_unlock(struct children_kddm_object *obj)
{
	pid_t tgid = obj->tgid;

	if (obj->write_locked)
		up_write(&obj->sem);
	else
		up_read(&obj->sem);

	_kddm_put_object(children_kddm_set, tgid);
}

static
struct children_kddm_object *
children_alloc(struct task_struct *task, pid_t tgid)
{
	struct children_kddm_object *obj;

	/* Filter well known cases of no children kddm object. */
	BUG_ON(!(tgid & GLOBAL_PID_MASK));

	obj = children_create_writelock(tgid);
	if (obj) {
		obj->nr_threads = 1;
		obj->self_exec_id = task->self_exec_id;
		rcu_assign_pointer(task->children_obj, obj);
		krg_children_unlock(obj);
	}

	return obj;
}

struct children_kddm_object *krg_children_alloc(struct task_struct *task)
{
	return children_alloc(task, task_tgid_knr(task));
}

static void free_children(struct task_struct *task)
{
	struct children_kddm_object *obj = task->children_obj;

	BUG_ON(!obj);
	BUG_ON(!list_empty(&obj->children));
	BUG_ON(obj->nr_threads);

	rcu_assign_pointer(task->children_obj, NULL);

	up_write(&obj->sem);
	_kddm_remove_frozen_object(children_kddm_set, obj->tgid);
}

void __krg_children_share(struct task_struct *task)
{
	struct children_kddm_object *obj = task->children_obj;
	obj->nr_threads++;
}

void krg_children_share(struct task_struct *task)
{
	struct children_kddm_object *obj = task->children_obj;

	obj = krg_children_writelock(obj->tgid);
	BUG_ON(!obj);
	BUG_ON(obj != task->children_obj);
	__krg_children_share(task);
	krg_children_unlock(obj);

}

/* Must be called under krg_children_writelock */
void krg_children_exit(struct task_struct *task)
{
	struct children_kddm_object *obj = task->children_obj;
	int free;

	free = !(--obj->nr_threads);
	if (free) {
		free_children(task);
	} else {
		rcu_assign_pointer(task->children_obj, NULL);
		krg_children_unlock(obj);
	}
}

static int krg_children_alive(struct children_kddm_object *obj)
{
	return obj && obj->alive;
}

static int new_child(struct children_kddm_object *obj,
		     pid_t parent_pid,
		     struct pid *pid, struct pid *tgid,
		     struct pid *pgrp, struct pid *session,
		     int exit_signal)
{
	struct remote_child *item;

	if (!obj)
		return 0;
	BUG_ON(parent_pid == 1);

	item = kmem_cache_alloc(remote_child_cachep, GFP_ATOMIC);
	if (!item)
		return -ENOMEM;

	item->pid = pid_knr(pid);
	item->tgid = pid_knr(tgid);
	item->pgid = pid_knr(pgrp);
	item->sid = pid_knr(session);
	item->parent = item->real_parent = parent_pid;
	item->ptraced = 0;
	item->exit_signal = exit_signal;
	item->exit_state = 0;
	item->node = kerrighed_node_id;
	set_child_links(obj, item);
	obj->nr_children++;

	return 0;
}

int krg_new_child(struct children_kddm_object *obj,
		  pid_t parent_pid,
		  struct task_struct *child)
{
	return new_child(obj, parent_pid, task_pid(child), task_tgid(child),
			 task_pgrp(child), task_session(child),
			 child->exit_signal);
}

/* Expects obj write locked */
void __krg_set_child_pgid(struct children_kddm_object *obj,
			  pid_t pid, pid_t pgid)
{
	struct remote_child *item;

	if (!obj)
		return;

	list_for_each_entry(item, &obj->children, sibling)
		if (item->pid == pid) {
			item->pgid = pgid;
			break;
		}
}

void krg_set_child_pgid(struct children_kddm_object *obj,
			struct task_struct *child)
{
	__krg_set_child_pgid(obj, task_pid_knr(child), task_pgrp_knr(child));
}

int krg_set_child_ptraced(struct children_kddm_object *obj,
			  struct task_struct *child, int ptraced)
{
	pid_t pid = task_pid_knr(child);
	struct remote_child *item;

	if (unlikely(!obj))
		return 0;

	list_for_each_entry(item, &obj->children, sibling)
		if (item->pid == pid) {
			if (ptraced && item->ptraced)
				return -EBUSY;
			item->ptraced = ptraced;
			return 0;
		}
	BUG();
	return -ECHILD;
}

/* Expects obj write locked */
void krg_set_child_exit_signal(struct children_kddm_object *obj,
			       struct task_struct *child)
{
	pid_t pid = task_pid_knr(child);
	struct remote_child *item;

	if (!obj)
		return;

	list_for_each_entry(item, &obj->children, sibling)
		if (item->pid == pid) {
			item->exit_signal = child->exit_signal;
			break;
		}
}

/* Expects obj write locked */
void krg_set_child_exit_state(struct children_kddm_object *obj,
			      struct task_struct *child)
{
	pid_t pid = task_pid_knr(child);
	struct remote_child *item;

	if (!obj)
		return;

	list_for_each_entry(item, &obj->children, sibling)
		if (item->pid == pid) {
			item->exit_state = child->exit_state;
			break;
		}
}

void krg_set_child_location(struct children_kddm_object *obj,
			    struct task_struct *child)
{
	pid_t pid = task_pid_knr(child);
	struct remote_child *item;

	if (!obj)
		return;

	list_for_each_entry(item, &obj->children, sibling)
		if (item->pid == pid) {
			item->node = kerrighed_node_id;
			break;
		}
}

/* Expects obj write locked */
static void remove_child(struct children_kddm_object *obj,
			 struct remote_child *child)
{
	remove_child_links(obj, child);
	kmem_cache_free(remote_child_cachep, child);
	obj->nr_children--;
}

static void reparent_child(struct children_kddm_object *obj,
			   struct remote_child *child,
			   pid_t reaper_pid, int same_group)
{
	/*
	 * A child can be reparented:
	 * either to another thread of the same thread group,
	 * or to its child reaper -> local child reaper
	 */

	BUG_ON(child->real_parent == reaper_pid);
	if (!same_group)
		/*
		 * Local child reaper doesn't need a children
		 * kddm object
		 */
		/* TODO: Is it true with PID namespaces? */
		remove_child(obj, child);
	else {
		BUG_ON(!(reaper_pid & GLOBAL_PID_MASK));
		/*
		 * For ptraced children, child->parent was already wrong since
		 * it is not assigned when ptrace-attaching. So keep it wrong
		 * the same way.
		 */
		child->parent = child->real_parent = reaper_pid;
	}
}

/*
 * Expects parent->children_obj write locked
 * and tasklist_lock write locked
 */
void krg_forget_original_remote_parent(struct task_struct *parent,
				       struct task_struct *reaper)
{
	int threaded_reparent = same_thread_group(reaper, parent);
	struct children_kddm_object *obj = parent->children_obj;
	struct remote_child *child, *tmp_child;
	pid_t ppid = task_pid_knr(parent);

	list_for_each_entry_safe(child, tmp_child, &obj->children, sibling)
		if (child->real_parent == ppid) {
			if (!threaded_reparent
			    && child->exit_state == EXIT_ZOMBIE
			    && child->node != kerrighed_node_id)
				/* Have it reaped by its local child reaper */
				/* Asynchronous */
				notify_remote_child_reaper(child->pid,
							   child->node);
			reparent_child(obj, child,
				       task_pid_knr(reaper), threaded_reparent);
		}
}

/* Expects obj write locked */
void
krg_remove_child(struct children_kddm_object *obj, struct task_struct *child)
{
	pid_t child_pid = task_pid_knr(child);
	struct remote_child *item;

	if (!obj)
		return;

	list_for_each_entry(item, &obj->children, sibling)
		if (item->pid == child_pid) {
			remove_child(obj, item);
			break;
		}
}

/* Expects obj at least read locked */
static int is_child(struct children_kddm_object *obj, pid_t pid)
{
	struct remote_child *item;
	int retval = 0;

	if (!obj)
		return 0;

	list_for_each_entry(item, &obj->children, sibling)
		if (item->pid == pid) {
			retval = 1;
			break;
		}

	return retval;
}

static int krg_eligible_child(struct children_kddm_object *obj,
			      enum pid_type type, pid_t pid, int options,
			      struct remote_child *child)
{
	int retval = 0;

	switch (type) {
	case PIDTYPE_PID:
		if (child->pid != pid)
			goto out;
		break;
	case PIDTYPE_PGID:
		if (child->pgid != pid)
			goto out;
		break;
	case PIDTYPE_MAX:
		break;
	default:
		BUG();
	}

	/* Wait for all children (clone and not) if __WALL is set;
	 * otherwise, wait for clone children *only* if __WCLONE is
	 * set; otherwise, wait for non-clone children *only*.  (Note:
	 * A "clone" child here is one that reports to its parent
	 * using a signal other than SIGCHLD.) */
	if (((child->exit_signal != SIGCHLD) ^ ((options & __WCLONE) != 0))
	    && !(options & __WALL))
		goto out;

	/* No support for remote LSM check */

	retval = 1;

out:
	return retval;
}

static int krg_delay_group_leader(struct remote_child *child)
{
	return child->pid == child->tgid && !list_empty(&child->thread_group);
}

static
bool krg_wait_consider_task(struct children_kddm_object *obj,
			    struct remote_child *child,
			    int *notask_error,
			    enum pid_type type, pid_t pid, int options,
			    struct siginfo __user *infop, int __user *stat_addr,
			    struct rusage __user *ru,
			    int *tsk_result)
{
	int ret;

	ret = krg_eligible_child(obj, type, pid, options, child);
	if (!ret)
		return false;

/*         if (unlikely(ret < 0)) { */
/*                 |+ */
/*                  * If we have not yet seen any eligible child, */
/*                  * then let this error code replace -ECHILD. */
/*                  * A permission error will give the user a clue */
/*                  * to look for security policy problems, rather */
/*                  * than for mysterious wait bugs. */
/*                  +| */
/*                 if (*notask_error) */
/*                         *notask_error = ret; */
/*         } */

	if (unlikely(child->ptraced)) {
		/*
		 * This child is hidden by ptrace.
		 * We aren't allowed to see it now, but eventually we will.
		 */
		*notask_error = 0;
		return false;
	}

	/*
	 * item->exit_state should not reach EXIT_DEAD since this can
	 * only happen when a thread self-reaps, and the thread is
	 * removed from its parent's children object before releasing
	 * the lock on it.
	 */
	BUG_ON(child->exit_state == EXIT_DEAD);

	/*
	 * We don't reap group leaders with subthreads.
	 */
	if (child->exit_state == EXIT_ZOMBIE
	    && !krg_delay_group_leader(child)) {
		/* Avoid doing an RPC when we already know the result */
		if (!likely(options & WEXITED))
			return false;

		krg_children_unlock(current->children_obj);
		*tsk_result = krg_wait_task_zombie(child->pid, child->node,
						   options,
						   infop, stat_addr, ru);
		return true;
	}

	/*
	 * It's stopped or running now, so it might
	 * later continue, exit, or stop again.
	 */
	*notask_error = 0;

	/* Check for stopped and continued task is not implemented right now. */
	return false;
}

/*
 * Expects obj locked. Releases obj lock.
 *
 * @return	pid (> 1) of task reaped, if any (init cannot be reaped), or
 *		0 and
 *		 0 in *notask_error if some tasks could be reaped later, or
 *		 *notask_error untouched if no task will be ever reapable, or
 *		 negative error code in *notask_error if an error occurs when
 *			reaping a task (do_wait() should abort)
 */
int krg_do_wait(struct children_kddm_object *obj, int *notask_error,
		enum pid_type type, pid_t pid, int options,
		struct siginfo __user *infop, int __user *stat_addr,
		struct rusage __user *ru)
{
	struct remote_child *item;
	pid_t current_pid = task_pid_knr(current);
	int ret = 0;

	if (!is_krg_pid_ns_root(current->nsproxy->pid_ns))
		goto out_unlock;

	/*
	 * Children attached by ptrace cannot be remote, so we only examine
	 * regular children.
	 */

retry:
	/* Remote version of do_wait_thread() */
	list_for_each_entry(item, &obj->children, sibling) {
		if ((options & __WNOTHREAD)
		    && item->real_parent != current_pid)
			continue;

		/*
		 * Do not consider detached threads.
		 */
		if (item->exit_signal != -1) {
			if (krg_wait_consider_task(obj, item, notask_error,
						     type, pid, options,
						     infop, stat_addr, ru,
						     &ret)) {
				if (ret)
					goto out;
				/* Raced with another thread. Retry. */
				__krg_children_readlock(current);
				goto retry;
			}
		}
	}

out_unlock:
	krg_children_unlock(current->children_obj);
out:
	return ret;
}

void krg_update_self_exec_id(struct task_struct *task)
{
	struct children_kddm_object *obj;

	if (rcu_dereference(task->children_obj)) {
		obj = __krg_children_writelock(task);
		BUG_ON(!obj);
		obj->self_exec_id = task->self_exec_id;
		krg_children_unlock(obj);
	}
}

u32 krg_get_real_parent_self_exec_id(struct task_struct *task,
				     struct children_kddm_object *obj)
{
	u32 id;

	if (task->real_parent == baby_sitter)
		id = obj->self_exec_id;
	else
		id = task->real_parent->self_exec_id;

	return id;
}

/* Must be called under rcu_read_lock() */
pid_t krg_get_real_parent_tgid(struct task_struct *task,
			       struct pid_namespace *ns)
{
	pid_t real_parent_tgid;
	struct task_struct *real_parent = rcu_dereference(task->real_parent);

	if (!pid_alive(task))
		return 0;

	if (real_parent != baby_sitter) {
		real_parent_tgid = task_tgid_nr_ns(real_parent, ns);
	} else if (!ns->krg_ns_root) {
		/*
		 * ns is an ancestor of task's root Kerrighed namespace, and
		 * thus has no names for remote parents.
		 */
		real_parent_tgid = 0;
	} else {
		struct task_kddm_object *task_obj =
			rcu_dereference(task->task_obj);
		struct children_kddm_object *parent_children_obj =
			rcu_dereference(task->parent_children_obj);

		BUG_ON(!is_krg_pid_ns_root(ns));

		if (task_obj && krg_children_alive(parent_children_obj)) {
			real_parent_tgid = task_obj->real_parent_tgid;
		} else {
			struct pid_namespace *_ns = task_active_pid_ns(task);
			if (_ns) {
				BUG_ON(_ns != ns);
				real_parent_tgid = 1;
			} else {
				real_parent_tgid = 0;
			}
		}
	}

	return real_parent_tgid;
}

/* Expects obj locked */
int __krg_get_parent(struct children_kddm_object *obj, pid_t pid,
		     pid_t *parent_pid, pid_t *real_parent_pid)
{
	struct remote_child *item;
	int retval = -ESRCH;

	if (!obj)
		goto out;

	list_for_each_entry(item, &obj->children, sibling)
		if (item->pid == pid) {
			*parent_pid = item->parent;
			*real_parent_pid = item->real_parent;
			retval = 0;
			goto out;
		}

out:
	return retval;
}

int krg_get_parent(struct children_kddm_object *obj, struct task_struct *child,
		   pid_t *parent_pid, pid_t *real_parent_pid)
{
	return __krg_get_parent(obj, task_pid_knr(child),
				parent_pid, real_parent_pid);
}

struct children_kddm_object *
krg_parent_children_writelock(struct task_struct *task, pid_t *parent_tgid)
{
	struct children_kddm_object *obj;
	struct pid_namespace *ns = task_active_pid_ns(task)->krg_ns_root;
	pid_t tgid, reaper_tgid;

	BUG_ON(!ns);
	rcu_read_lock();
	tgid = krg_get_real_parent_tgid(task, ns);
	obj = rcu_dereference(task->parent_children_obj);
	rcu_read_unlock();
	BUG_ON(!tgid);
	reaper_tgid = task_tgid_knr(task_active_pid_ns(task)->child_reaper);
	if (!obj || tgid == reaper_tgid) {
		obj = NULL;
		goto out;
	}

	obj = krg_children_writelock(tgid);
	/*
	 * Check that thread group tgid is really the parent of task.
	 * If not, unlock obj immediately, and return NULL.
	 *
	 * is_child may also return 0 if task's parent is init. In that case, it
	 * is still correct to return NULL as long as parent_tgid is set.
	 */
	if (!is_child(obj, task_pid_knr(task))) {
		if (obj)
			krg_children_unlock(obj);
		obj = NULL;
		tgid = reaper_tgid;
		goto out;
	}

out:
	*parent_tgid = tgid;
	return obj;
}

struct children_kddm_object *
krg_parent_children_readlock(struct task_struct *task, pid_t *parent_tgid)
{
	struct children_kddm_object *obj;
	struct pid_namespace *ns = task_active_pid_ns(task)->krg_ns_root;
	pid_t tgid, reaper_tgid;

	BUG_ON(!ns);
	rcu_read_lock();
	tgid = krg_get_real_parent_tgid(task, ns);
	obj = rcu_dereference(task->parent_children_obj);
	rcu_read_unlock();
	BUG_ON(!tgid);
	reaper_tgid = task_tgid_knr(task_active_pid_ns(task)->child_reaper);
	if (!obj || tgid == reaper_tgid) {
		obj = NULL;
		goto out;
	}

	obj = krg_children_readlock(tgid);
	/*
	 * Check that thread group tgid is really the parent of task.
	 * If not, unlock obj immediately, and return NULL.
	 *
	 * is_child may also return 0 if task's parent is init. In that case, it
	 * is still correct to return NULL as long as parent_tgid is set.
	 */
	if (!is_child(obj, task_pid_knr(task))) {
		if (obj)
			krg_children_unlock(obj);
		obj = NULL;
		tgid = reaper_tgid;
		goto out;
	}

out:
	*parent_tgid = tgid;
	return obj;
}

pid_t krg_get_real_parent_pid(struct task_struct *task)
{
	struct children_kddm_object *parent_obj;
	pid_t real_parent_pid, parent_pid, real_parent_tgid;

	if (task->real_parent != baby_sitter)
		return task_pid_vnr(task->real_parent);

	BUG_ON(!is_krg_pid_ns_root(current->nsproxy->pid_ns));
	parent_obj = krg_parent_children_readlock(task, &real_parent_tgid);
	if (!parent_obj) {
		real_parent_pid = 1;
	} else {
		/* gcc ... */
		real_parent_pid = 0;
		krg_get_parent(parent_obj, task,
			       &parent_pid, &real_parent_pid);
		krg_children_unlock(parent_obj);
	}

	return real_parent_pid;
}
EXPORT_SYMBOL(krg_get_real_parent_pid);

/************************************************************************
 * Local children list of a task					*
 ************************************************************************/

static inline struct list_head *new_krg_parent_entry(pid_t key)
{
	struct list_head *entry;

	entry = kmem_cache_alloc(krg_parent_head_cachep, GFP_ATOMIC);
	if (!entry)
		return NULL;

	INIT_LIST_HEAD(entry);
	__hashtable_add(krg_parent_table, key, entry);

	return entry;
}

static inline struct list_head *get_krg_parent_entry(pid_t key)
{
	return __hashtable_find(krg_parent_table, key);
}

static inline void delete_krg_parent_entry(pid_t key)
{
	struct list_head *entry;

	entry = __hashtable_find(krg_parent_table, key);
	BUG_ON(!entry);
	BUG_ON(!list_empty(entry));

	__hashtable_remove(krg_parent_table, key);
	kmem_cache_free(krg_parent_head_cachep, entry);
}

static inline void add_to_krg_parent(struct task_struct *tsk, pid_t parent_pid)
{
	struct list_head *children;

	children = get_krg_parent_entry(parent_pid);
	if (children == NULL) {
		children = new_krg_parent_entry(parent_pid);
		if (!children)
			OOM;
	}
	list_add_tail(&tsk->sibling, children);
}

static inline void remove_from_krg_parent(struct task_struct *tsk,
					  pid_t parent_pid)
{
	struct list_head *children;

	children = get_krg_parent_entry(parent_pid);
	BUG_ON(!children);

	list_del(&tsk->sibling);
	if (list_empty(children))
		delete_krg_parent_entry(parent_pid);
}

/*
 * Used in two cases:
 * 1/ When child considers its parent as remote, and this parent is now local
 *    -> link directly in parent's children list
 * 2/ When child considers its parent as local, and parent is leaving the node
 *    -> unlink child from any process children list,
 *       and add it to its parent's entry in krg_parent table
 * In both cases, child->real_parent is assumed to be correctly set according to
 * the desired result.
 */
static inline void fix_chain_to_parent(struct task_struct *child,
				       pid_t parent_pid)
{
	if (child->real_parent != baby_sitter) {
		/* Child may be still linked in baby_sitter's children */
		list_move_tail(&child->sibling, &child->real_parent->children);
		return;
	}

	/*
	 * At this point, child is chained in baby_sitter's or local parent's
	 * children.
	 * Fix this right now.
	 */
	list_del(&child->sibling);
	add_to_krg_parent(child, parent_pid);
}

/*
 * Parent was remote, and can now be considered as local for its local children
 * Relink all its local children in its children list
 *
 * Assumes at least a read lock on parent's children kddm object
 */
static inline void rechain_local_children(struct task_struct *parent)
{
	pid_t ppid = task_pid_knr(parent);
	struct list_head *children;
	struct task_struct *child, *tmp;

	children = get_krg_parent_entry(ppid);
	if (!children)
		return;

	list_for_each_entry_safe(child, tmp, children, sibling) {
		/* TODO: This will need more serious work to support ptrace */
		/*
		 * If parent has reused a pid, this krg_parent list may still
		 * contain children of a former user of this pid.
		 */
		if (!likely(is_child(parent->children_obj, task_pid_knr(child))))
			continue;
		child->real_parent = parent;
		list_move_tail(&child->sibling, &parent->children);
		if (child->parent == baby_sitter &&
		    child->task_obj->parent == ppid)
			child->parent = parent;
	}

	if (likely(list_empty(children)))
		delete_krg_parent_entry(ppid);
}

/* Expects write lock on tasklist held */
static inline void update_links(struct task_struct *orphan)
{
	fix_chain_to_parent(orphan, orphan->task_obj->real_parent);
	rechain_local_children(orphan);
}

static inline struct task_struct *find_relative(pid_t pid)
{
	struct task_struct *p;

	p = find_task_by_kpid(pid);
	if (p && !unlikely(p->flags & PF_AWAY))
		return p;
	else
		return baby_sitter;
}

static inline struct task_struct *find_live_relative(pid_t pid)
{
	struct task_struct *p;

	p = find_relative(pid);
	if (p != baby_sitter && (p->flags & PF_EXITING))
		return baby_sitter;
	else
		return p;
}

static void update_relatives(struct task_struct *task)
{
	struct task_kddm_object *task_obj = task->task_obj;

	/*
	 * In case of local (real_)parent's death, delay reparenting as if
	 * (real_)parent was still remote
	 */
	if (task->parent == baby_sitter)
		task->parent = find_live_relative(task_obj->parent);
	if (task->real_parent == baby_sitter)
		task->real_parent = find_live_relative(task_obj->real_parent);
	if (task->group_leader == baby_sitter)
		task->group_leader = find_relative(task_obj->group_leader);
}

/* Used by import_process() */
void join_local_relatives(struct task_struct *orphan)
{
	__krg_children_readlock(orphan);
	write_lock_irq(&tasklist_lock);

	/*
	 * Need to do it early to avoid a group leader task to consider itself
	 * as remote when updating the group leader pointer
	 */
	orphan->flags &= ~PF_AWAY;

	update_relatives(orphan);
	update_links(orphan);

	write_unlock_irq(&tasklist_lock);
	krg_children_unlock(orphan->children_obj);
}

/* Expects write lock on tasklist held */
static void __reparent_to_baby_sitter(struct task_struct *orphan,
				      pid_t parend_pid)
{
	orphan->parent = baby_sitter;

	if (orphan->real_parent == baby_sitter)
		return;
	orphan->real_parent = baby_sitter;
	list_move_tail(&orphan->sibling, &baby_sitter->children);
}

/* Expects write lock on tasklist held */
static void reparent_to_baby_sitter(struct task_struct *orphan,
				    pid_t parent_pid)
{
	__reparent_to_baby_sitter(orphan, parent_pid);
	fix_chain_to_parent(orphan, parent_pid);
}

/* Expects write lock on tasklist held */
static void leave_baby_sitter(struct task_struct *tsk, pid_t old_parent)
{
	BUG_ON(tsk->real_parent != baby_sitter);
	update_relatives(tsk);
	BUG_ON(tsk->parent == baby_sitter);
	BUG_ON(tsk->real_parent == baby_sitter);

	remove_from_krg_parent(tsk, old_parent);
	list_add_tail(&tsk->sibling, &tsk->real_parent->children);
}

/*
 * Used by migration
 * Expects write lock on tsk->task_obj object held
 */
void leave_all_relatives(struct task_struct *tsk)
{
	struct task_struct *child, *tmp;

	write_lock_irq(&tasklist_lock);

	tsk->flags |= PF_AWAY;

	/*
	 * Update task_obj in case parent exited while
	 * we were chained in its regular children list
	 */
	if (tsk->parent != baby_sitter)
		tsk->task_obj->parent = task_pid_knr(tsk->parent);
	if (tsk->real_parent != baby_sitter) {
		tsk->task_obj->real_parent = task_pid_knr(tsk->real_parent);
		tsk->task_obj->real_parent_tgid = task_tgid_knr(tsk->real_parent);
	}

	/* Make local children act as if tsk were already remote */
	list_for_each_entry_safe(child, tmp, &tsk->children, sibling)
		reparent_to_baby_sitter(child, task_pid_knr(tsk));

	/* Make parent act as if tsk were already remote */
	if (tsk->real_parent == baby_sitter) {
		/*
		 * parent is remote, but tsk is still linked to the local
		 * children list of its parent
		 */
		remove_from_krg_parent(tsk, tsk->task_obj->real_parent);
		list_add_tail(&tsk->sibling, &baby_sitter->children);
	} else {
		__reparent_to_baby_sitter(tsk, task_pid_knr(tsk->real_parent));
	}

	write_unlock_irq(&tasklist_lock);
}

/* Per syscall hooks */

/* fork() */

int krg_children_prepare_fork(struct task_struct *task,
			      struct pid *pid,
			      unsigned long clone_flags)
{
	struct children_kddm_object *obj, *parent_obj;
	pid_t tgid;
	int err = 0;

	rcu_assign_pointer(task->children_obj, NULL);
	rcu_assign_pointer(task->parent_children_obj, NULL);

	if (!is_krg_pid_ns_root(task->nsproxy->pid_ns))
		goto out;

	if (krg_current) {
		rcu_assign_pointer(task->children_obj,
				   krg_current->children_obj);
		BUG_ON(!task->children_obj);
		rcu_assign_pointer(task->parent_children_obj,
				   krg_current->parent_children_obj);
		goto out;
	}

	if (clone_flags & CLONE_THREAD)
		tgid = task_tgid_knr(current);
	else
		tgid = pid_knr(pid);

	/* Kernel threads and local pids must not use the children kddm set. */
	if (!(tgid & GLOBAL_PID_MASK) || (current->flags & PF_KTHREAD))
		goto out;

	/* Attach task to the children kddm object of its thread group */
	if (!(clone_flags & CLONE_THREAD)) {
		obj = children_alloc(task, tgid);
		if (!obj) {
			err = -ENOMEM;
			goto out;
		}
		rcu_assign_pointer(task->children_obj, obj);
	} else {
		obj = current->children_obj;
		if (obj) {
			rcu_assign_pointer(task->children_obj, obj);
			krg_children_share(task);
		}
	}

	/* Prepare to put task in the children kddm object of its parent */
	if ((clone_flags & (CLONE_PARENT | CLONE_THREAD))) {
		pid_t parent_tgid;
		parent_obj = krg_parent_children_writelock(current,
							   &parent_tgid);
	} else {
		parent_obj = __krg_children_writelock(current);
	}
	krg_children_get(parent_obj);
	rcu_assign_pointer(task->parent_children_obj, parent_obj);

out:
	return err;
}

int krg_children_fork(struct task_struct *task,
		      struct pid *pid,
		      unsigned long clone_flags)
{
	struct children_kddm_object *obj = task->parent_children_obj;
	pid_t parent_pid;
	struct pid *tgid;
	int err = 0;

	if (krg_current)
		goto out;

	if (!obj)
		goto out;

	if (task->real_parent == baby_sitter)
		/*
		 * task's task_obj is not setup yet, but
		 * one of CLONE_THREAD and CLONE_PARENT must be set, so we can
		 * use current's task_obj.
		 */
		parent_pid = current->task_obj->real_parent;
	else
		parent_pid = task_pid_knr(task->real_parent);
	tgid = pid;
	if (clone_flags & CLONE_THREAD)
		tgid = task_tgid(current);
	err = new_child(obj, parent_pid,
			pid, tgid,
			task_pgrp(current), task_session(current),
			task->exit_signal);

	if (!err && task->real_parent == baby_sitter)
		add_to_krg_parent(task, parent_pid);

out:
	return err;
}

void krg_children_commit_fork(struct task_struct *task)
{
	struct children_kddm_object *parent_obj = task->parent_children_obj;

	if (!krg_current && parent_obj)
		krg_children_unlock(parent_obj);
}

void krg_children_abort_fork(struct task_struct *task)
{
	struct children_kddm_object *parent_obj = task->parent_children_obj;
	struct children_kddm_object *obj = task->children_obj;

	if (krg_current)
		return;

	if (parent_obj) {
		krg_children_unlock(parent_obj);
		krg_children_put(parent_obj);
	}

	if (obj) {
		krg_children_writelock(obj->tgid);
		krg_children_exit(task);
	}
}

/* de_thread() (execve()) */

/* Expects tasklist writelocked */
static void krg_children_unlink_krg_parent(struct task_struct *task)
{
	if (task->real_parent == baby_sitter) {
		/*
		 * leader will lose its task KDDM object, make it a
		 * simple child of baby_sitter.
		 */
		remove_from_krg_parent(task, task->task_obj->real_parent);
		list_add_tail(&task->sibling, &baby_sitter->children);
	}
}

/* Expects tasklist writelocked */
static void krg_children_relink_krg_parent(struct task_struct *task)
{
	if (task->real_parent == baby_sitter) {
		list_del(&task->sibling);
		add_to_krg_parent(task, task->task_obj->real_parent);
	}
}

struct children_kddm_object *
krg_children_prepare_de_thread(struct task_struct *task)
{
	struct children_kddm_object *obj = NULL;
	struct task_struct *leader = task->group_leader;
	pid_t real_parent_tgid;

	if (rcu_dereference(task->parent_children_obj)) {
		obj = krg_parent_children_writelock(task, &real_parent_tgid);
		write_lock_irq(&tasklist_lock);
		/*
		 * leader should not be considered as a child after the PID
		 * switch.
		 */
		krg_children_unlink_krg_parent(leader);
		/*
		 * krg_parent may change because leader's
		 * task_obj will be more up to date.
		 */
		krg_children_unlink_krg_parent(task);
		write_unlock_irq(&tasklist_lock);
		krg_remove_child(obj, task);
	}
	if (rcu_dereference(task->children_obj)) {
		struct children_kddm_object *children_obj;

		children_obj = __krg_children_writelock(task);
		BUG_ON(!children_obj);
		/*
		 * All children were reparented to task, but the children
		 * object knows them as children of task's pid, while task
		 * is taking leader's pid.
		 * krg_forget_original_remote_parent() will only record
		 * the pid of leader, so this is safe.
		 */
		krg_forget_original_remote_parent(task, leader);
	}

	return obj;
}

void krg_children_finish_de_thread(struct children_kddm_object *obj,
				   struct task_struct *task)
{
	if (rcu_dereference(task->children_obj))
		krg_children_unlock(task->children_obj);
	if (obj) {
		write_lock_irq(&tasklist_lock);
		krg_children_relink_krg_parent(task);
		write_unlock_irq(&tasklist_lock);
		krg_set_child_exit_signal(obj, task);
		krg_set_child_exit_state(obj, task);
		krg_children_unlock(obj);
	}
}

/* exit()/release_task() */

/* Expects tasklist and task KDDM object writelocked */
void
krg_update_parents(struct task_struct *task, pid_t parent, pid_t real_parent)
{
	if (task->real_parent == baby_sitter) {
		remove_from_krg_parent(task, task->task_obj->real_parent);
		list_add_tail(&task->sibling, &baby_sitter->children);
	}
	task->task_obj->parent = parent;
	task->task_obj->real_parent = real_parent;
	update_relatives(task);
	fix_chain_to_parent(task, real_parent);
}

/* Expects task kddm object write locked and tasklist lock write locked */
void krg_reparent_to_local_child_reaper(struct task_struct *task)
{
	struct task_kddm_object *task_obj = task->task_obj;
	struct task_struct *reaper = task_active_pid_ns(task)->child_reaper;
	pid_t parent_pid, reaper_pid, reaper_tgid;

	/*
	 * If task is ptraced, the ptracer is local and we can safely set
	 * task_obj->parent to parent's pid.
	 */
	parent_pid = task_obj->real_parent;
	reaper_pid = task_pid_knr(reaper);
	reaper_tgid = task_tgid_knr(reaper);
	task_obj->real_parent = reaper_pid;
	task_obj->real_parent_tgid = reaper_tgid;
	if (task->parent == baby_sitter)
		task_obj->parent = reaper_pid;
	else
		BUG_ON(task_obj->parent != task_pid_knr(task->parent));
	leave_baby_sitter(task, parent_pid);
	BUG_ON(task->real_parent != reaper);
	BUG_ON(task->parent == baby_sitter);

	if (!task_detached(task))
		task->exit_signal = SIGCHLD;
}

void krg_unhash_process(struct task_struct *tsk)
{
	pid_t real_parent_tgid;
	struct children_kddm_object *obj;

	if (!task_active_pid_ns(tsk)->krg_ns_root)
		return;

	if (tsk->exit_state == EXIT_MIGRATION)
		return;

	/*
	 * If we are inside de_thread() and tsk is an old thread group leader
	 * being reaped by the new thread group leader, we do not want to remove
	 * tsk's pid from the global children list of tsk's parent.
	 * Moreover tsk is already reparented to baby_sitter, so we have nothing
	 * to do here.
	 */
	if (has_group_leader_pid(tsk) && !thread_group_leader(tsk))
		return;

	obj = krg_parent_children_writelock(tsk, &real_parent_tgid);
	/*
	 * After that, obj may still be NULL if real_parent does not
	 * have a children kddm object.
	 */
	/* Won't do anything if obj is NULL. */
	krg_remove_child(obj, tsk);
	write_lock_irq(&tasklist_lock);
	if (tsk->real_parent == baby_sitter) {
		remove_from_krg_parent(tsk, tsk->task_obj->real_parent);
		list_add_tail(&tsk->sibling, &baby_sitter->children);
	}
	write_unlock_irq(&tasklist_lock);
	if (obj)
		krg_children_unlock(obj);
}

void krg_children_cleanup(struct task_struct *task)
{
	struct children_kddm_object *obj = task->parent_children_obj;

	if (obj) {
		rcu_assign_pointer(task->parent_children_obj, NULL);
		krg_children_put(obj);
	}
}

/**
 * @author Louis Rilling
 */
void epm_children_start(void)
{
	unsigned long cache_flags = SLAB_PANIC;

#ifdef CONFIG_DEBUG_SLAB
	cache_flags |= SLAB_POISON;
#endif
	children_obj_cachep = KMEM_CACHE(children_kddm_object, cache_flags);
	remote_child_cachep = KMEM_CACHE(remote_child,cache_flags);
	krg_parent_head_cachep = kmem_cache_create("krg_parent_head",
						   sizeof(struct list_head),
						   sizeof(void *), cache_flags,
						   NULL);

	register_io_linker(CHILDREN_LINKER, &children_io_linker);

	children_kddm_set = create_new_kddm_set(kddm_def_ns,CHILDREN_KDDM_ID,
						CHILDREN_LINKER,
						KDDM_CUSTOM_DEF_OWNER,
						0, 0);
	if (IS_ERR(children_kddm_set))
		OOM;
	krg_parent_table = hashtable_new(PROCESS_HASH_TABLE_SIZE);
	if (!krg_parent_table)
		OOM;
}

/**
 * @author Louis Rilling
 */
void epm_children_exit(void)
{
	hashtable_free(krg_parent_table);
}
