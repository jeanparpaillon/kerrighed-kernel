/*
 *  kerrighed/epm/pid.c
 *
 *  Copyright (C) 2006-2007 Pascal Gallard - Kerlabs, Louis Rilling - Kerlabs
 */

#include <linux/types.h>
#include <linux/pid.h>
#include <linux/pid_namespace.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/lockdep.h>
#include <linux/rcupdate.h>
#include <linux/workqueue.h>
#include <kerrighed/pid.h>
#include <kerrighed/task.h>
#include <kerrighed/workqueue.h>
#include <kerrighed/namespace.h>
#include <net/krgrpc/rpcid.h>
#include <net/krgrpc/rpc.h>
#include <kerrighed/hotplug.h>
#include <kddm/kddm.h>
#include <kddm/object_server.h>
#include <kerrighed/ghost.h>
#include <kerrighed/ghost_helpers.h>
#include <kerrighed/action.h>
#include <kerrighed/application.h>
#include <kerrighed/libproc.h>

#include <linux/delay.h>

#include "pid.h"

struct pid_kddm_object {
	struct list_head wq;
	struct rcu_head rcu;
	struct pid *pid;
	int attach_pending;
	int active;
	struct task_kddm_object *task_obj;
	/* This is the only field shared through kddm. */
	int node_count;
};

static struct kmem_cache *pid_kddm_obj_cachep;
static DEFINE_SPINLOCK(pid_kddm_lock);
static struct kddm_set *pid_kddm_set;

static LIST_HEAD(put_pid_wq_head);
static DEFINE_SPINLOCK(put_pid_wq_lock);
static struct work_struct put_pid_work;

/*
 * @author Pascal Gallard
 */
static int pid_alloc_object(struct kddm_obj *obj_entry,
			    struct kddm_set *set, objid_t objid)
{
	struct pid_kddm_object *p;

	p = kmem_cache_alloc(pid_kddm_obj_cachep, GFP_KERNEL);
	if (!p)
		return -ENOMEM;

	INIT_LIST_HEAD(&p->wq);
	p->pid = NULL;
	p->attach_pending = 0;
	p->active = 0;
	p->task_obj = NULL;
	obj_entry->object = p;

	return 0;
}

/*
 * @author Pascal Gallard
 */
static int pid_first_touch(struct kddm_obj *obj_entry,
			   struct kddm_set *set, objid_t objid, int flags)
{
	struct pid_kddm_object *obj;
	int r;

	BUG_ON(obj_entry->object);

	r = pid_alloc_object(obj_entry, set, objid);
	if (r)
		return r;

	obj = obj_entry->object;
	/* Can be false in case of restart */
	/* BUG_ON(ORIG_NODE(objid) != kerrighed_node_id); */
	obj->node_count = 1; /* For the node having created the PID */
	return 0;
}

/*
 * @author Pascal Gallard
 */
static int pid_import_object(struct rpc_desc *desc,
			     struct kddm_set *set,
			     struct kddm_obj *obj_entry,
			     objid_t objid,
			     int flags)
{
	struct pid_kddm_object *obj = obj_entry->object;

	return rpc_unpack_type(desc, obj->node_count);
}

/*
 * @author Pascal Gallard
 */
static int pid_export_object(struct rpc_desc *desc,
			     struct kddm_set *set,
			     struct kddm_obj *obj_entry,
			     objid_t objid,
			     int flags)
{
	struct pid_kddm_object *obj = obj_entry->object;

	return rpc_pack_type(desc, obj->node_count);
}

static void delayed_pid_free(struct rcu_head *rhp)
{
	struct pid_kddm_object *obj =
		container_of(rhp, struct pid_kddm_object, rcu);

	kmem_cache_free(pid_kddm_obj_cachep, obj);
}

static int pid_remove_object(void *object,
			     struct kddm_set *set, objid_t objid)
{
	struct pid_kddm_object *obj = object;
	struct pid *pid = obj->pid;

	spin_lock(&pid_kddm_lock);
	pid->kddm_obj = NULL;
	obj->pid = NULL;
	spin_unlock(&pid_kddm_lock);
	free_pid(pid);

	rcu_read_lock();
	krg_pid_unlink_task(obj);
	rcu_read_unlock();

	call_rcu(&obj->rcu, delayed_pid_free);

	return 0;
}

static struct iolinker_struct pid_io_linker = {
	.first_touch   = pid_first_touch,
	.linker_name   = "pid ",
	.linker_id     = PID_LINKER,
	.alloc_object  = pid_alloc_object,
	.export_object = pid_export_object,
	.import_object = pid_import_object,
	.remove_object = pid_remove_object,
	.default_owner = global_pid_default_owner,
};

static void __get_pid(struct pid_kddm_object *obj)
{
	obj->attach_pending++;
	if (!obj->active) {
		obj->node_count++;
		obj->active = 1;
	}
}

static struct pid *no_pid(int nr)
{
	struct pid_namespace *ns;
	struct pid_kddm_object *obj;
	struct pid *pid;

	obj = _kddm_grab_object_no_ft(pid_kddm_set, nr);
	if (IS_ERR(obj))
		return NULL;
	BUG_ON(!obj);

	spin_lock(&pid_kddm_lock);
	rcu_read_lock();
	pid = find_kpid(nr); /* Double check once locked */
	rcu_read_unlock();
	/*
	 * No need to get a reference on pid since we know that it is used on
	 * another node: nobody will free it for the moment.
	 */

	if (!pid) {
		ns = find_get_krg_pid_ns();
		pid = __alloc_pid(ns, &nr);
		put_pid_ns(ns);
		if (!pid)
			goto out_unlock;
		obj->pid = pid;
		pid->kddm_obj = obj;
	}
	BUG_ON(pid->kddm_obj != obj);

	__get_pid(obj);

out_unlock:
	spin_unlock(&pid_kddm_lock);
	_kddm_put_object(pid_kddm_set, nr);

	return pid;
}

struct pid *krg_get_pid(int nr)
{
	struct pid_kddm_object *obj;
	struct pid *pid;

	rcu_read_lock();
	pid = find_kpid(nr);
	rcu_read_unlock();
	/*
	 * No need to get a reference on pid since we know that it is used on
	 * another node: nobody will free it for the moment.
	 */

	if (!pid)
		return no_pid(nr);

	spin_lock(&pid_kddm_lock);
	obj = pid->kddm_obj;
	BUG_ON(!obj);
	BUG_ON(obj->pid != pid);

	if (likely(obj->active)) {
		obj->attach_pending++;
		spin_unlock(&pid_kddm_lock);
		return pid;
	}
	/* Slow path: we must grab the kddm object. */
	spin_unlock(&pid_kddm_lock);

	obj = _kddm_grab_object_no_ft(pid_kddm_set, nr);
	if (IS_ERR(obj))
		return NULL;
	BUG_ON(obj != pid->kddm_obj);
	BUG_ON(obj->pid != pid);

	spin_lock(&pid_kddm_lock);
	__get_pid(obj);
	spin_unlock(&pid_kddm_lock);

	_kddm_put_object(pid_kddm_set, nr);

	return pid;
}

void krg_end_get_pid(struct pid *pid)
{
	struct pid_kddm_object *obj = pid->kddm_obj;

	spin_lock(&pid_kddm_lock);
	BUG_ON(!obj);
	obj->attach_pending--;
	BUG_ON(obj->attach_pending < 0);
	spin_unlock(&pid_kddm_lock);
}

static int may_put_pid(struct pid_kddm_object *obj)
{
	struct pid *pid = obj->pid;
	int tmp;

	if (obj->attach_pending || !obj->active)
		return 0;
	/* Check if this PID is used by a task struct on this node */
	for (tmp = PIDTYPE_MAX; --tmp >= 0; )
		if (!hlist_empty(&pid->tasks[tmp]))
			return 0;

	return 1;
}

static void __put_pid(struct pid_kddm_object *obj)
{
	struct pid *pid = obj->pid;
	int nr = pid_knr(pid);
	int may_put;
	int grabbed = 0;

	/* Try to avoid grabing the kddm object */
	read_lock(&tasklist_lock);
	spin_lock(&pid_kddm_lock);
	may_put = may_put_pid(obj);
	spin_unlock(&pid_kddm_lock);
	if (!may_put)
		goto release_work;
	read_unlock(&tasklist_lock);

	/* The pid seems to be unused locally. Have to check globally. */
	/* Prevent pidmaps from changing host nodes. */
	pidmap_map_read_lock();
	fkddm_grab_object(kddm_def_ns, PID_KDDM_ID, nr,
			  KDDM_NO_FT_REQ | KDDM_DONT_KILL);
	grabbed = 1;

	read_lock(&tasklist_lock);

	spin_lock(&pid_kddm_lock);
	may_put = may_put_pid(obj);
	if (may_put) {
		obj->active = 0;
		obj->node_count--;
		if (obj->node_count)
			/* Still used elsewhere */
			may_put = 0;
	}
	spin_unlock(&pid_kddm_lock);

release_work:
	spin_lock(&put_pid_wq_lock);
	list_del_init(&obj->wq);
	spin_unlock(&put_pid_wq_lock);

	read_unlock(&tasklist_lock);

	if (may_put) {
		_kddm_remove_frozen_object(pid_kddm_set, nr);
		pidmap_map_read_unlock();
	} else if (grabbed) {
		_kddm_put_object(pid_kddm_set, nr);
		pidmap_map_read_unlock();
	}
}

/* This worker cleans all PID related data on this node. */
static void put_pid_worker(struct work_struct *work)
{
	LIST_HEAD(work_list);
	struct pid_kddm_object *obj, *n;

	/* Remove the current job-list */
	spin_lock(&put_pid_wq_lock);
	list_splice_init(&put_pid_wq_head, &work_list);
	spin_unlock(&put_pid_wq_lock);

	list_for_each_entry_safe(obj, n, &work_list, wq)
		__put_pid(obj);
}

/*
 * Only place where IRQs may be disabled. This induces lockdep to believe that
 * deadlocks can occur whenever an IRQ handler takes pid_kddm_lock or
 * put_pid_wq_lock, but we know that no IRQ handler can do this.
 */
void krg_put_pid(struct pid *pid)
{
	struct pid_kddm_object *obj;

	lockdep_off();
	spin_lock(&pid_kddm_lock);
	obj = pid->kddm_obj;
	spin_lock(&put_pid_wq_lock);
	lockdep_on();

	if (obj && obj->active && list_empty(&obj->wq)) {
		BUG_ON(obj->pid != pid);
		list_add_tail(&obj->wq, &put_pid_wq_head);
		queue_work(krg_wq, &put_pid_work);
	}

	lockdep_off();
	spin_unlock(&put_pid_wq_lock);
	spin_unlock(&pid_kddm_lock);
	lockdep_on();

	if (!obj)
		free_pid(pid);
}

static int create_pid_kddm_object(struct pid *pid, int early)
{
	int nr = pid_knr(pid);
	struct pid_kddm_object *obj;
	struct task_kddm_object *task_obj;

	obj = _kddm_grab_object(pid_kddm_set, nr);
	if (IS_ERR(obj)) {
		_kddm_put_object(pid_kddm_set, nr);
		return PTR_ERR(obj);
	}
	BUG_ON(!obj);
	task_obj = krg_task_readlock(nr);

	spin_lock(&pid_kddm_lock);
	BUG_ON(early && pid->kddm_obj);
	if (!pid->kddm_obj) {
		obj->pid = pid;
		obj->active = 1;
		if (early)
			obj->attach_pending = 1;
		BUG_ON(obj->task_obj);
		if (task_obj) {
			BUG_ON(task_obj->pid_obj);
			/*
			 * These rcu_assign_pointer are not really needed,
			 * but are cleaner :)
			 */
			rcu_assign_pointer(obj->task_obj, task_obj);
			rcu_assign_pointer(obj->task_obj->pid_obj, obj);
		}
		pid->kddm_obj = obj;
	}
	BUG_ON(pid->kddm_obj != obj);
	spin_unlock(&pid_kddm_lock);

	krg_task_unlock(nr);
	_kddm_put_object(pid_kddm_set, nr);

	return 0;
}

int cr_create_pid_kddm_object(struct pid *pid)
{
	return create_pid_kddm_object(pid, 0);
}

int export_pid(struct epm_action *action,
	       ghost_t *ghost, struct pid_link *link)
{
	struct pid *pid = link->pid;
	int nr = pid_knr(pid);
	int retval;

	if (!(nr & GLOBAL_PID_MASK))
		return -EPERM;

	if (ORIG_NODE(nr) == kerrighed_node_id && !pid->kddm_obj
	    && action->type != EPM_CHECKPOINT) {
		retval = create_pid_kddm_object(pid, 0);
		if (retval)
			return retval;
	}
	return ghost_write(ghost, &nr, sizeof(nr));
}

int export_pid_namespace(struct epm_action *action,
			 ghost_t *ghost, struct task_struct *task)
{
	if (!is_krg_pid_ns_root(task_active_pid_ns(task))) {
		PANIC("Cannot export processes"
		      " using a non default PID namespace!\n");
		return -EINVAL;
	}

	return 0;
}

/*--------------------------------------------------------------------------*
 *--------------------------------------------------------------------------*/

static int __reserve_pid(pid_t nr)
{
	kerrighed_node_t orig_node = ORIG_NODE(nr);
	struct pid_namespace *pid_ns = find_get_krg_pid_ns();
	struct pid_namespace *pidmap_ns;
	struct pid *pid;
	int r;

	if (orig_node == kerrighed_node_id)
		pidmap_ns = pid_ns;
	else
		pidmap_ns = node_pidmap(orig_node);
	BUG_ON(!pidmap_ns);

	r = reserve_pidmap(pidmap_ns, nr);
	if (r) {
		r = -E_CR_PIDBUSY;
		goto out;
	}

	pid = __alloc_pid(pid_ns, &nr);
	if (!pid) {
		struct upid upid = {
			.nr = nr,
			.ns = pidmap_ns,
		};

		__free_pidmap(&upid);

		r = -ENOMEM;
		goto out;
	}

	/*
	 * this is not always mandatory but really difficult
	 * to know when it is or not
	 */
	r = create_pid_kddm_object(pid, 1);
	if (r)
		goto error;

out:
	put_pid_ns(pid_ns);
	return r;

error:
	free_pid(pid);
	goto out;
}

struct pid_reservation_msg {
	kerrighed_node_t requester;
	pid_t pid;
};

static int handle_reserve_pid(struct rpc_desc *desc, void *_msg, size_t size)
{
	struct pid_reservation_msg *msg = _msg;
	int r = __reserve_pid(msg->pid);
	return r;
}

int reserve_pid(long app_id, pid_t pid)
{
	int r;
	struct krg_namespace *ns;
	kerrighed_node_t orig_node = ORIG_NODE(pid);
	kerrighed_node_t host_node;
	struct pid_reservation_msg msg;

	msg.requester = kerrighed_node_id;
	msg.pid = pid;

	ns = find_get_krg_ns();

	r = pidmap_map_read_lock();
	if (r)
		goto out;

	host_node = pidmap_node(orig_node);
	if (host_node == KERRIGHED_NODE_ID_NONE) {
		pidmap_map_read_unlock();

		r = pidmap_map_alloc(orig_node);
		if (r)
			goto out;

		pidmap_map_read_lock();

		host_node = pidmap_node(orig_node);
		BUG_ON(host_node == KERRIGHED_NODE_ID_NONE);
	}

	r = rpc_sync(PROC_RESERVE_PID, ns->rpc_comm, host_node,
		     &msg, sizeof(msg));

	pidmap_map_read_unlock();

out:
	put_krg_ns(ns);
	if (r)
		app_error(__krg_action_to_str(EPM_RESTART), r, app_id,
			  "Fail to reserve pid %d", pid);

	return r;
}

static void __end_pid_reservation(int nr)
{
	struct pid *pid;

	rcu_read_lock();
	pid = find_kpid(nr);
	BUG_ON(!pid);

	krg_end_get_pid(pid);
	krg_put_pid(pid);
	rcu_read_unlock();
}

static int handle_end_pid_reservation(struct rpc_desc *desc, void *_msg,
				      size_t size)
{
	struct pid_reservation_msg *msg = _msg;
	__end_pid_reservation(msg->pid);
	return 0;
}

int end_pid_reservation(pid_t pid)
{
	int r;
	struct krg_namespace *ns;
	kerrighed_node_t host_node;
	struct pid_reservation_msg msg;

	msg.requester = kerrighed_node_id;
	msg.pid = pid;

	ns = find_get_krg_ns();

	r = pidmap_map_read_lock();
	if (r)
		goto out;

	host_node = pidmap_node(ORIG_NODE(pid));
	BUG_ON(host_node == KERRIGHED_NODE_ID_NONE);

	r = rpc_sync(PROC_END_PID_RESERVATION, ns->rpc_comm, host_node,
		     &msg, sizeof(msg));

	pidmap_map_read_unlock();

out:
	put_krg_ns(ns);

	return r;
}

/*--------------------------------------------------------------------------*
 *--------------------------------------------------------------------------*/

int import_pid(struct epm_action *action, ghost_t *ghost, struct pid_link *link,
	       enum pid_type type)
{
	struct pid *pid;
	int nr;
	int retval;

	retval = ghost_read(ghost, &nr, sizeof(nr));
	if (retval)
		return retval;

	if (action->type == EPM_RESTART) {
		if ((action->restart.flags & APP_REPLACE_PGRP)
		    && type == PIDTYPE_PGID)
			nr = action->restart.app->restart.substitution_pgrp;
		else if ((action->restart.flags & APP_REPLACE_SID)
			 && type == PIDTYPE_SID)
			nr = action->restart.app->restart.substitution_sid;
	}

	pid = krg_get_pid(nr);
	if (!pid)
		return -ENOMEM;
	INIT_HLIST_NODE(&link->node);
	link->pid = pid;

	return 0;
}

int import_pid_namespace(struct epm_action *action,
			 ghost_t *ghost, struct task_struct *task)
{
	task->nsproxy->pid_ns = find_get_krg_pid_ns();

	return 0;
}

void unimport_pid(struct pid_link *link)
{
	struct pid *pid = link->pid;

	if (pid->kddm_obj)
		krg_end_get_pid(pid);
	krg_put_pid(pid);
}

/* Must be called under rcu_read_lock() */
struct task_kddm_object *krg_pid_task(struct pid *pid)
{
	struct pid_kddm_object *obj;

	obj = rcu_dereference(pid->kddm_obj);
	if (obj)
		return rcu_dereference(obj->task_obj);
	return NULL;
}

/* Must be called under rcu_read_lock() */
void krg_pid_unlink_task(struct pid_kddm_object *obj)
{
	struct task_kddm_object *task_obj;

	if (obj) {
		task_obj = rcu_dereference(obj->task_obj);
		if (task_obj) {
			rcu_assign_pointer(task_obj->pid_obj, NULL);
			rcu_assign_pointer(obj->task_obj, NULL);
		}
	}
}

/*--------------------------------------------------------------------------*
 *--------------------------------------------------------------------------*/

struct pid_link_task_msg {
	kerrighed_node_t requester;
	pid_t pid;
};

int krg_pid_link_task(pid_t pid)
{
	struct pid_link_task_msg msg;
	struct krg_namespace *ns;
	kerrighed_node_t host_node;
	int r;

	msg.requester = kerrighed_node_id;
	msg.pid = pid;

	ns = find_get_krg_ns();

	r = pidmap_map_read_lock();
	if (r)
		goto out;

	host_node = pidmap_node(ORIG_NODE(pid));
	BUG_ON(host_node == KERRIGHED_NODE_ID_NONE);

	r = rpc_sync(PROC_PID_LINK_TASK, ns->rpc_comm, host_node,
		     &msg, sizeof(msg));

	pidmap_map_read_unlock();

out:
	put_krg_ns(ns);

	return r;
}

static void __pid_link_task(struct pid *pid, struct task_kddm_object *task_obj)
{
	if (task_obj && pid && pid->kddm_obj) {
		rcu_assign_pointer(pid->kddm_obj->task_obj, task_obj);
		rcu_assign_pointer(task_obj->pid_obj, pid->kddm_obj);
	}
}

int __krg_pid_link_task(pid_t nr)
{
	struct pid *pid;
	struct task_kddm_object *task_obj;
	int r = 0;

	pid = krg_get_pid(nr);
	if (!pid) {
		r = -ENOMEM;
		goto out;
	}
	task_obj = krg_task_readlock(nr);

	__pid_link_task(pid, task_obj);

	krg_task_unlock(nr);
	krg_end_get_pid(pid);
	krg_put_pid(pid);

out:
	return r;
}

static int handle_pid_link_task(struct rpc_desc *desc, void *_msg, size_t size)
{
	struct pid_link_task_msg *msg = _msg;

	return __krg_pid_link_task(msg->pid);
}

/*--------------------------------------------------------------------------*
 *--------------------------------------------------------------------------*/

void pid_wait_quiescent(void)
{
	flush_work(&put_pid_work);
}

static int pid_flusher(struct kddm_set *set, objid_t objid,
		       struct kddm_obj *obj_entry, void *data)
{
	return global_pid_default_owner(set, objid,
					&krgnode_online_map,
					num_online_krgnodes());
}

void pid_remove_local(void)
{
	_kddm_flush_set(pid_kddm_set, pid_flusher, NULL);
}

void epm_pid_start(void)
{
	unsigned long cache_flags = SLAB_PANIC;

#ifdef CONFIG_DEBUG_SLAB
	cache_flags |= SLAB_POISON;
#endif
	pid_kddm_obj_cachep = KMEM_CACHE(pid_kddm_object, cache_flags);

	INIT_WORK(&put_pid_work, put_pid_worker);

	register_io_linker(PID_LINKER, &pid_io_linker);
	pid_kddm_set = create_new_kddm_set(kddm_def_ns,
					   PID_KDDM_ID,
					   PID_LINKER,
					   KDDM_CUSTOM_DEF_OWNER,
					   0, 0);
	if (IS_ERR(pid_kddm_set))
		OOM;

	rpc_register_int(PROC_RESERVE_PID, handle_reserve_pid, 0);
	rpc_register_int(PROC_PID_LINK_TASK, handle_pid_link_task, 0);
	rpc_register_int(PROC_END_PID_RESERVATION,
			 handle_end_pid_reservation, 0);
}

void epm_pid_exit(void)
{
	return;
}
