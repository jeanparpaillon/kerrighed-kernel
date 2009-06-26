/*
 *  kerrighed/proc/task.c
 *
 *  Copyright (C) 1999-2006 INRIA, Universite de Rennes 1, EDF
 *  Copyright (C) 2006-2007 Pascal Gallard - Kerlabs, Louis Rilling - Kerlabs
 */

/** On each node the system manage a table to know the
 *  location of migrated process.
 *  It is interesting to globally manage signal : e.g. when a signal
 *  arrive from a remote node, the system can find the old local
 *  process pid and so the process'father.
 */

#include <linux/types.h>
#include <linux/module.h>
#include <linux/personality.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/cred.h>
#include <linux/rwsem.h>
#include <linux/lockdep.h>
#include <linux/rcupdate.h>
#include <linux/kref.h>
#include <linux/slab.h>
#include <kerrighed/task.h>
#include <kerrighed/pid.h>

#include "debug_proc.h"

#include <net/krgrpc/rpc.h>
#include <kerrighed/libproc.h>
#include <kddm/kddm.h>

static struct kmem_cache *task_kddm_obj_cachep;

/* kddm set of pid location and task struct */
static struct kddm_set *task_kddm_set;

void krg_task_get(struct task_kddm_object *obj)
{
	if (obj) {
		kref_get(&obj->kref);
		DEBUG(DBG_TASK_KDDM, 4, "%d count=%d\n",
		      obj->pid, atomic_read(&obj->kref.refcount));
	}
}

static void task_free(struct kref *kref)
{
	struct task_kddm_object *obj;

	obj = container_of(kref, struct task_kddm_object, kref);
	BUG_ON(!obj);

	DEBUG(DBG_TASK_KDDM, 2, "%d\n", obj->pid);

	kmem_cache_free(task_kddm_obj_cachep, obj);
}

void krg_task_put(struct task_kddm_object *obj)
{
	if (obj) {
		DEBUG(DBG_TASK_KDDM, 4, "%d count=%d\n",
		      obj->pid, atomic_read(&obj->kref.refcount));
		kref_put(&obj->kref, task_free);
	}
}

/*
 * @author Pascal Gallard
 */
static int task_alloc_object(struct kddm_obj *obj_entry,
			     struct kddm_set *set, objid_t objid)
{
	struct task_kddm_object *p;

	DEBUG(DBG_TASK_KDDM, 4, "%lu\n", objid);
	p = kmem_cache_alloc(task_kddm_obj_cachep, GFP_KERNEL);
	if (!p)
		return -ENOMEM;

	DEBUG(DBG_TASK_KDDM, 3, "%lu 0x%p\n", objid, p);
	p->node = KERRIGHED_NODE_ID_NONE;
	p->task = NULL;
	p->pid = objid;
	p->parent_node = KERRIGHED_NODE_ID_NONE;
	/*
	 * If the group leader is another thread, this
	 * will be fixed later. Before that this is
	 * only needed to check local/global pids.
	 */
	p->group_leader = objid;
#ifdef CONFIG_KRG_EPM
	p->pid_obj = NULL;
#endif
	init_rwsem(&p->sem);
	p->write_locked = 0;

	p->alive = 1;
	kref_init(&p->kref);
	obj_entry->object = p;

	return 0;
}

/*
 * @author Pascal Gallard
 */
static int task_first_touch(struct kddm_obj *obj_entry,
			    struct kddm_set *set, objid_t objid, int flags)
{
	return task_alloc_object(obj_entry, set, objid);
}

/*
 * @author Pascal Gallard
 */
static int task_import_object(struct rpc_desc *desc,
			      struct kddm_set *set,
			      struct kddm_obj *obj_entry,
			      objid_t objid,
			      int flags)
{
	struct task_kddm_object *dest = obj_entry->object;
	struct task_kddm_object src;
	int retval;

	DEBUG(DBG_TASK_KDDM, 3, "%d dest=0x%p\n", dest->pid, dest);

	retval = rpc_unpack_type(desc, src);
	if (retval)
		return retval;

	write_lock_irq(&tasklist_lock);

	dest->state = src.state;
	dest->flags = src.flags;
	dest->ptrace = src.ptrace;
	dest->exit_state = src.exit_state;
	dest->exit_code = src.exit_code;
	dest->exit_signal = src.exit_signal;

	dest->node = src.node;
	dest->self_exec_id = src.self_exec_id;
	dest->thread_group_empty = src.thread_group_empty;

	dest->parent = src.parent;
	dest->parent_node = src.parent_node;
	dest->real_parent = src.real_parent;
	dest->real_parent_tgid = src.real_parent_tgid;
	dest->group_leader = src.group_leader;

	dest->uid = src.uid;
	dest->euid = src.euid;
	dest->egid = src.egid;

	dest->utime = src.utime;
	dest->stime = src.stime;

	dest->dumpable = src.dumpable;

	write_unlock_irq(&tasklist_lock);

	return 0;
}

/*
 * Assumes either tasklist_lock read locked with appropriate task_lock held, or
 * tasklist_lock write locked.
 */
static void task_update_object(struct task_kddm_object *obj)
{
	struct task_struct *tsk = obj->task;
	const struct cred *cred;

	if (tsk) {
		BUG_ON(tsk->task_obj != obj);

		obj->state = tsk->state;
		obj->flags = tsk->flags;
		obj->ptrace = tsk->ptrace;
		obj->exit_state = tsk->exit_state;
		obj->exit_code = tsk->exit_code;
		obj->exit_signal = tsk->exit_signal;

		obj->self_exec_id = tsk->self_exec_id;

		BUG_ON(obj->node != kerrighed_node_id &&
		       obj->node != KERRIGHED_NODE_ID_NONE);

		rcu_read_lock();
		cred = __task_cred(tsk);
		obj->uid = cred->uid;
		obj->euid = cred->euid;
		obj->egid = cred->egid;
		rcu_read_unlock();

		obj->utime = task_utime(tsk);
		obj->stime = task_stime(tsk);

		obj->dumpable = (tsk->mm && get_dumpable(tsk->mm) == 1);

		obj->thread_group_empty = thread_group_empty(tsk);
	}
}

/*
 * @author Pascal Gallard
 */
static int task_export_object(struct rpc_desc *desc,
			      struct kddm_set *set,
			      struct kddm_obj *obj_entry,
			      objid_t objid,
			      int flags)
{
	struct task_kddm_object *src = obj_entry->object;
	struct task_struct *tsk;

	DEBUG(DBG_TASK_KDDM, 3, "%d src=0x%p\n", src->pid, src);

	read_lock(&tasklist_lock);
	tsk = src->task;
	if (likely(tsk)) {
		task_lock(tsk);
		task_update_object(src);
		task_unlock(tsk);
	}
	read_unlock(&tasklist_lock);

	return rpc_pack_type(desc, *src);
}

static void delayed_task_put(struct rcu_head *rhp)
{
	struct task_kddm_object *obj =
		container_of(rhp, struct task_kddm_object, rcu);

	krg_task_put(obj);
}

/**
 *  @author Louis Rilling
 */
static int task_remove_object(void *object,
			      struct kddm_set *set, objid_t objid)
{
	struct task_kddm_object *obj = object;

	DEBUG(DBG_TASK_KDDM, 3, "%d 0x%p\n", obj->pid, obj);

	krg_task_unlink(obj, 0);

#ifdef CONFIG_KRG_EPM
	rcu_read_lock();
	krg_pid_unlink_task(rcu_dereference(obj->pid_obj));
	rcu_read_unlock();
	BUG_ON(obj->pid_obj);
#endif

	obj->alive = 0;
	call_rcu(&obj->rcu, delayed_task_put);

	return 0;
}

static struct iolinker_struct task_io_linker = {
	.first_touch   = task_first_touch,
	.linker_name   = "task ",
	.linker_id     = TASK_LINKER,
	.alloc_object  = task_alloc_object,
	.export_object = task_export_object,
	.import_object = task_import_object,
	.remove_object = task_remove_object,
	.default_owner = global_pid_default_owner,
};

int krg_task_alloc(struct task_struct *task, struct pid *pid)
{
	struct task_kddm_object *obj;
	int nr = pid_knr(pid);

	task->task_obj = NULL;
	if (!task->nsproxy->krg_ns)
		return 0;
#ifdef CONFIG_KRG_EPM
	if (krg_current)
		return 0;
#endif
	/* Exclude kernel threads and local pids from using task kddm objects. */
	/*
	 * At this stage, current->mm points the mm of the task being duplicated
	 * instead of the mm of task for which this struct is being allocated,
	 * but we only need to know whether it is NULL or not, which will be the
	 * same after copy_mm.
	 */
	if (!(nr & GLOBAL_PID_MASK) || !current->mm)
		return 0;

	obj = krg_task_create_writelock(nr);
	if (!obj)
		return -ENOMEM;

	/* Set the link between task kddm object and tsk */
	obj->task = task;
	task->task_obj = obj;

	return 0;
}

void krg_task_fill(struct task_struct *task, unsigned long clone_flags)
{
	struct task_kddm_object *obj = task->task_obj;

	BUG_ON((task_tgid_knr(task) & GLOBAL_PID_MASK)
	       != (task_pid_knr(task) & GLOBAL_PID_MASK));

#ifdef CONFIG_KRG_EPM
	if (krg_current)
		return;
#endif
	if (!obj)
		return;

	obj->node = kerrighed_node_id;
#ifdef CONFIG_KRG_EPM
	if (task->real_parent == baby_sitter) {
		BUG_ON(!current->task_obj);
		if (clone_flags & (CLONE_PARENT|CLONE_THREAD)) {
			struct task_kddm_object *cur_obj = current->task_obj;
			obj->real_parent = cur_obj->real_parent;
			obj->real_parent_tgid = cur_obj->real_parent_tgid;
		} else {
			obj->real_parent = task_pid_knr(current);
			obj->real_parent_tgid = task_tgid_knr(current);
		}
	} else
#endif
	{
		obj->real_parent = task_pid_knr(task->real_parent);
		obj->real_parent_tgid = task_tgid_knr(task->real_parent);
	}
	/* Keep parent same as real_parent until ptrace is better supported */
	obj->parent = obj->real_parent;
#ifdef CONFIG_KRG_EPM
	/* Distributed threads are not supported yet. */
	BUG_ON(task->group_leader == baby_sitter);
#endif
	obj->group_leader = task_tgid_knr(task);
}

void krg_task_commit(struct task_struct *task)
{
	if (task->task_obj)
		__krg_task_unlock(task);
}

void krg_task_abort(struct task_struct *task)
{
	struct task_kddm_object *obj = task->task_obj;

#ifdef CONFIG_KRG_EPM
	if (krg_current)
		return;
#endif

	if (!obj)
		return;

	obj->write_locked = 2;
	up_write(&obj->sem);

	_kddm_remove_frozen_object(task_kddm_set, obj->pid);
}

void __krg_task_free(struct task_struct *task)
{
	DEBUG(DBG_TASK_KDDM, 2, "%d\n", task_pid_knr(task));
	_kddm_remove_object(task_kddm_set, task_pid_knr(task));
}

void krg_task_free(struct task_struct *task)
{
	/* If the pointer is NULL and the object exists, this is a BUG! */
	if (!task->task_obj)
		return;

	__krg_task_free(task);
}

/* Expects tasklist write locked */
void __krg_task_unlink(struct task_kddm_object *obj, int need_update)
{
	BUG_ON(!obj);

	DEBUG(DBG_TASK_KDDM, 2, "%d\n", obj->pid);
	if (obj->task) {
		if (need_update)
			task_update_object(obj);
		rcu_assign_pointer(obj->task->task_obj, NULL);
		rcu_assign_pointer(obj->task, NULL);
	}
}

void krg_task_unlink(struct task_kddm_object *obj, int need_update)
{
	write_lock_irq(&tasklist_lock);
	__krg_task_unlink(obj, need_update);
	write_unlock_irq(&tasklist_lock);
}

int krg_task_alive(struct task_kddm_object *obj)
{
	return obj && obj->alive;
}

/**
 * @author Pascal Gallard
 */
struct task_kddm_object *krg_task_readlock(pid_t pid)
{
	struct task_kddm_object *obj;

	/* Filter well known cases of no task kddm object. */
	if (!(pid & GLOBAL_PID_MASK))
		return NULL;

	obj = _kddm_get_object_no_ft(task_kddm_set, pid);
	if (likely(obj)) {
		down_read(&obj->sem);
		if (obj->write_locked == 2) {
			/* Dying object */
			up_read(&obj->sem);
			_kddm_put_object(task_kddm_set, pid);
			return NULL;
		}
		/* Marker for unlock. Dirty but temporary. */
		obj->write_locked = 0;
	}
	DEBUG(DBG_TASK_KDDM, 2, "%d (0x%p)\n", pid, obj);

	return obj;
}

struct task_kddm_object *__krg_task_readlock(struct task_struct *task)
{
	return krg_task_readlock(task_pid_knr(task));
}

/**
 * @author Pascal Gallard
 */
static struct task_kddm_object *task_writelock(pid_t pid, int nested)
{
	struct task_kddm_object *obj;

	/* Filter well known cases of no task kddm object. */
	if (!(pid & GLOBAL_PID_MASK))
		return NULL;

	obj = _kddm_grab_object_no_ft(task_kddm_set, pid);
	if (likely(obj)) {
		if (!nested)
			down_write(&obj->sem);
		else
			down_write_nested(&obj->sem, SINGLE_DEPTH_NESTING);
		if (obj->write_locked == 2) {
			/* Dying object */
			up_write(&obj->sem);
			_kddm_put_object(task_kddm_set, pid);
			return NULL;
		}
		/* Marker for unlock. Dirty but temporary. */
		obj->write_locked = 1;
	}
	DEBUG(DBG_TASK_KDDM, 2, "%d (0x%p)\n", pid, obj);

	return obj;
}

struct task_kddm_object *krg_task_writelock(pid_t pid)
{
	return task_writelock(pid, 0);
}

struct task_kddm_object *__krg_task_writelock(struct task_struct *task)
{
	return task_writelock(task_pid_knr(task), 0);
}

struct task_kddm_object *krg_task_writelock_nested(pid_t pid)
{
	return task_writelock(pid, 1);
}

struct task_kddm_object *__krg_task_writelock_nested(struct task_struct *task)
{
	return task_writelock(task_pid_knr(task), 1);
}

/**
 * @author Louis Rilling
 */
struct task_kddm_object *krg_task_create_writelock(pid_t pid)
{
	struct task_kddm_object *obj;

	/* Filter well known cases of no task kddm object. */
	/* The exact filter is expected to be implemented by the caller. */
	BUG_ON(!(pid & GLOBAL_PID_MASK));

	obj = _kddm_grab_object(task_kddm_set, pid);
	if (likely(obj && !IS_ERR(obj))) {
		down_write(&obj->sem);
		/* No dying object race or this is really smelly */
		BUG_ON(obj->write_locked == 2);
		/* Marker for unlock. Dirty but temporary. */
		obj->write_locked = 1;
	} else {
		_kddm_put_object(task_kddm_set, pid);
	}
	DEBUG(DBG_TASK_KDDM, 2, "%d (0x%p)\n", pid, obj);

	return obj;
}

/**
 * @author Pascal Gallard
 */
void krg_task_unlock(pid_t pid)
{
	/* Filter well known cases of no task kddm object. */
	if (!(pid & GLOBAL_PID_MASK))
		return;

	DEBUG(DBG_TASK_KDDM, 2, "%d\n", pid);
	{
		/*
		 * Dirty tricks here. Hopefully it should be temporary waiting
		 * for kddm to implement locking on a task basis.
		 */
		struct task_kddm_object *obj;

		obj = _kddm_find_object(task_kddm_set, pid);
		if (likely(obj)) {
			_kddm_put_object(task_kddm_set, pid);
			if (obj->write_locked)
				up_write(&obj->sem);
			else
				up_read(&obj->sem);
		}
	}
	_kddm_put_object(task_kddm_set, pid);
}

void __krg_task_unlock(struct task_struct *task)
{
	krg_task_unlock(task_pid_knr(task));
}

#ifdef CONFIG_KRG_EPM
/**
 * @author Pascal Gallard
 * Set (or update) the location of pid
 */
int krg_set_pid_location(struct task_struct *task)
{
	struct task_kddm_object *p;

	p = __krg_task_writelock(task);
	if (likely(p))
		p->node = kerrighed_node_id;
	__krg_task_unlock(task);

	return 0;
}

int krg_unset_pid_location(struct task_struct *task)
{
	struct task_kddm_object *p;

	BUG_ON(!(task_pid_knr(task) & GLOBAL_PID_MASK));

	p = __krg_task_writelock(task);
	BUG_ON(p == NULL);
	p->node = KERRIGHED_NODE_ID_NONE;
	__krg_task_unlock(task);

	return 0;
}
#endif /* CONFIG_KRG_EPM */

kerrighed_node_t krg_lock_pid_location(pid_t pid)
{
	kerrighed_node_t node = KERRIGHED_NODE_ID_NONE;
	struct task_kddm_object *obj;
#ifdef CONFIG_KRG_EPM
	struct timespec back_off_time = {
		.tv_sec = 0,
		.tv_nsec = 1000000 /* 1 ms */
	};
#endif

	if (!(pid & GLOBAL_PID_MASK))
		goto out;

	for (;;) {
		obj = krg_task_readlock(pid);
		if (likely(obj)) {
			node = obj->node;
		} else {
			krg_task_unlock(pid);
			break;
		}
#ifdef CONFIG_KRG_EPM
		if (likely(node != KERRIGHED_NODE_ID_NONE))
			break;
		DEBUG(DBG_TASK_KDDM, 4, "%s node=%d, backing off\n",
		      current->comm, node);
		/*
		 * Task is migrating.
		 * Back off and hope that it will stop migrating.
		 */
		krg_task_unlock(pid);
		set_current_state(TASK_UNINTERRUPTIBLE);
		schedule_timeout(timespec_to_jiffies(&back_off_time) + 1);
#else
		break;
#endif
	}

out:
	return node;
}

void krg_unlock_pid_location(pid_t pid)
{
	krg_task_unlock(pid);
}

/**
 * @author David Margery
 * @author Pascal Gallard (update to kddm architecture)
 * @author Louis Rilling (split files)
 */
void proc_task_start(void)
{
	unsigned long cache_flags = SLAB_PANIC;

#ifdef CONFIG_DEBUG_SLAB
	cache_flags |= SLAB_POISON;
#endif
	task_kddm_obj_cachep = KMEM_CACHE(task_kddm_object, cache_flags);

	register_io_linker(TASK_LINKER, &task_io_linker);

	task_kddm_set = create_new_kddm_set(kddm_def_ns, TASK_KDDM_ID,
					    TASK_LINKER,
					    KDDM_CUSTOM_DEF_OWNER,
					    0, 0);
	if (IS_ERR(task_kddm_set))
		OOM;

	DEBUG(DBG_TASK_KDDM, 1, "Done\n");
}

/**
 * @author David Margery
 * @author Pascal Gallard (update to kddm architecture)
 * @author Louis Rilling (split files)
 */
void proc_task_exit(void)
{
}
