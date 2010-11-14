/*
 *  Kerrighed/modules/ipc/sem_handler.c
 *
 *  All the code for sharing IPC semaphore accross the cluster
 *
 *  Copyright (C) 2007-2008 Matthieu Fertré - INRIA
 */
#include <linux/ipc.h>
#include <linux/ipc_namespace.h>
#include <linux/msg.h>
#include <linux/sem.h>
#include <linux/semaphore.h>
#include <linux/nsproxy.h>
#include <kddm/kddm.h>
#include <kddm/kddm_flush_object.h>
#include <kerrighed/pid.h>
#include <net/krgrpc/rpc.h>
#include <kerrighed/hotplug.h>
#include "ipc_handler.h"
#include "sem_handler.h"
#include "semarray_io_linker.h"
#include "semundolst_io_linker.h"
#include "ipcmap_io_linker.h"
#include "util.h"
#include "krgsem.h"

struct semkrgops {
	struct krgipc_ops krgops;
	struct kddm_set *undo_list_kddm_set;

	/* unique_id generator for sem_undo_list identifier */
	unique_id_root_t undo_list_unique_id_root;
};

struct kddm_set *krgipc_ops_undolist_set(struct krgipc_ops *ipcops)
{
	struct semkrgops *semops;

	semops = container_of(ipcops, struct semkrgops, krgops);

	return semops->undo_list_kddm_set;
}

struct kddm_set *task_undolist_set(struct task_struct *task)
{
	struct ipc_namespace *ns;

	ns = task_nsproxy(task)->ipc_ns;
	if (!sem_ids(ns).krgops)
		return ERR_PTR(-EINVAL);

	return krgipc_ops_undolist_set(sem_ids(ns).krgops);
}

/*****************************************************************************/
/*                                                                           */
/*                                KERNEL HOOKS                               */
/*                                                                           */
/*****************************************************************************/

static struct kern_ipc_perm *kcb_ipc_sem_lock(struct ipc_ids *ids, int id)
{
	semarray_object_t *sem_object;
	struct sem_array *sma;
	int index ;

	index = ipcid_to_idx(id);

	sem_object = _kddm_grab_object_no_ft(ids->krgops->data_kddm_set, index);

	if (!sem_object)
		goto error;

	sma = sem_object->local_sem;

	BUG_ON(!sma);

	mutex_lock(&sma->sem_perm.mutex);

	BUG_ON(sma->sem_perm.deleted);

	return &(sma->sem_perm);

error:
	_kddm_put_object(ids->krgops->data_kddm_set, index);

	return ERR_PTR(-EINVAL);
}

static void kcb_ipc_sem_unlock(struct kern_ipc_perm *ipcp)
{
	int index;
	long task_state;

	/*
	 * We may enter in interruptible state, and kddm_put_object might
	 * schedule and reset to running.
	 * Fortunately, wakeup only happens with ipcp->mutex held, so we can
	 * restore the state right before mutex_unlock.
	 */
	task_state = current->state;

	index = ipcid_to_idx(ipcp->id);

	BUG_ON(ipcp->deleted);

	_kddm_put_object(ipcp->krgops->data_kddm_set, index);

	__set_current_state(task_state);

	mutex_unlock(&ipcp->mutex);
}

static struct kern_ipc_perm *kcb_ipc_sem_findkey(struct ipc_ids *ids, key_t key)
{
	long *key_index;
	int id = -1;

	key_index = _kddm_get_object_no_ft(ids->krgops->key_kddm_set, key);

	if (key_index)
		id = *key_index;

	_kddm_put_object(ids->krgops->key_kddm_set, key);

	if (id != -1)
		return kcb_ipc_sem_lock(ids, id);

	return NULL;
}

/** Notify the creation of a new IPC sem_array to Kerrighed.
 *
 *  @author Matthieu Fertré
 */
int krg_ipc_sem_newary(struct ipc_namespace *ns, struct sem_array *sma)
{
	semarray_object_t *sem_object;
	long *key_index;
	int index ;

	BUG_ON(!sem_ids(ns).krgops);

	index = ipcid_to_idx(sma->sem_perm.id);

	sem_object = _kddm_grab_object_manual_ft(
		sem_ids(ns).krgops->data_kddm_set, index);

	BUG_ON(sem_object);

	sem_object = kmem_cache_alloc(semarray_object_cachep, GFP_KERNEL);
	if (!sem_object)
		return -ENOMEM;

	sem_object->local_sem = sma;
	sem_object->mobile_sem_base = NULL;
	sem_object->imported_sem = *sma;

	/* there are no pending objects for the moment */
	BUG_ON(!list_empty(&sma->sem_pending));
	BUG_ON(!list_empty(&sma->remote_sem_pending));

	INIT_LIST_HEAD(&sem_object->imported_sem.list_id);
	INIT_LIST_HEAD(&sem_object->imported_sem.sem_pending);
	INIT_LIST_HEAD(&sem_object->imported_sem.remote_sem_pending);

	_kddm_set_object(sem_ids(ns).krgops->data_kddm_set, index, sem_object);

	if (sma->sem_perm.key != IPC_PRIVATE)
	{
		key_index = _kddm_grab_object(sem_ids(ns).krgops->key_kddm_set,
					      sma->sem_perm.key);
		*key_index = index;
		_kddm_put_object(sem_ids(ns).krgops->key_kddm_set,
				 sma->sem_perm.key);
	}

	_kddm_put_object(sem_ids(ns).krgops->data_kddm_set, index);

	sma->sem_perm.krgops = sem_ids(ns).krgops;

	return 0;
}

static inline void __remove_semundo_from_proc_list(struct sem_array *sma,
						   unique_id_t proc_list_id)
{
	struct semundo_id * undo_id, *next, *prev;
	struct kddm_set *undo_list_set;
	struct semundo_list_object *undo_list;

	undo_list_set = krgipc_ops_undolist_set(sma->sem_perm.krgops);

	undo_list = _kddm_grab_object_no_ft(undo_list_set, proc_list_id);

	if (!undo_list)
		goto exit;

	prev = NULL;
	for (undo_id = undo_list->list; undo_id; undo_id = next) {
		next = undo_id->next;

		if (undo_id->semid == sma->sem_perm.id) {
			atomic_dec(&undo_list->semcnt);
			kfree(undo_id);
			if (!prev)
				undo_list->list = next;
			else
				prev->next = next;

			goto exit;
		}
		prev = undo_id;
	}
	BUG();

exit:
	_kddm_put_object(undo_list_set, proc_list_id);
}

void krg_ipc_sem_freeary(struct ipc_namespace *ns, struct kern_ipc_perm *ipcp)
{
	int index;
	struct sem_undo* un, *tu;
	struct sem_array *sma = container_of(ipcp, struct sem_array, sem_perm);

	index = ipcid_to_idx(ipcp->id);

	/* removing the related semundo from the list per process */
	list_for_each_entry_safe(un, tu, &sma->list_id, list_id) {
		list_del(&un->list_id);
		__remove_semundo_from_proc_list(sma, un->proc_list_id);
		kfree(un);
	}

	if (ipcp->key != IPC_PRIVATE) {
		_kddm_grab_object(sem_ids(ns).krgops->key_kddm_set,
				  ipcp->key);
		_kddm_remove_frozen_object(sem_ids(ns).krgops->key_kddm_set,
					   ipcp->key);
	}

	local_sem_unlock(sma);
	_kddm_remove_frozen_object(sem_ids(ns).krgops->data_kddm_set, index);

	krg_ipc_rmid(&sem_ids(ns), index);
}

struct ipcsem_wakeup_msg {
	kerrighed_node_t requester;
	int sem_id;
	pid_t pid;
	int error;
};

void handle_ipcsem_wakeup_process(struct rpc_desc *desc, void *_msg,
				  size_t size)
{
	struct ipcsem_wakeup_msg *msg = _msg;
	struct sem_array *sma;
	struct sem_queue *q, *tq;
	struct ipc_namespace *ns;

	ns = find_get_krg_ipcns();
	BUG_ON(!ns);

	/* take only a local lock because the requester node has the kddm lock
	   on the semarray */
	sma = local_sem_lock(ns, msg->sem_id);
	BUG_ON(IS_ERR(sma));

	list_for_each_entry_safe(q, tq, &sma->sem_pending, list) {
		/* compare to q->sleeper's pid instead of q->pid
		   because q->pid == q->sleeper's tgid */
		if (task_pid_knr(q->sleeper) == msg->pid) {
			list_del(&q->list);
			goto found;
		}
	}

	BUG();
found:
	q->status = 1; /* IN_WAKEUP; */

	BUG_ON(!q->sleeper);
	BUG_ON(q->pid != task_tgid_nr_ns(q->sleeper,
					 task_active_pid_ns(q->sleeper)));

	wake_up_process(q->sleeper);
	smp_wmb();
	q->status = msg->error;

	local_sem_unlock(sma);

	rpc_pack_type(desc, msg->error);

	put_ipc_ns(ns);
}

void krg_ipc_sem_wakeup_process(struct sem_array *sma, struct sem_queue *q,
				int error)
{
	struct ipcsem_wakeup_msg msg;
	struct rpc_desc *desc;

	msg.requester = kerrighed_node_id;
	msg.sem_id = q->semid;
	msg.pid = remote_sleeper_pid(q); /* q->pid contains the tgid */
	msg.error = error;

	desc = rpc_begin(IPC_SEM_WAKEUP, q->node);
	rpc_pack_type(desc, msg);
	rpc_unpack_type(desc, msg.error);
	rpc_end(desc, 0);
}

static inline struct semundo_list_object * __create_semundo_proc_list(
	struct task_struct *task, struct kddm_set *undo_list_set)
{
	unique_id_t undo_list_id;
	struct semundo_list_object *undo_list;
	struct ipc_namespace *ns;
	struct semkrgops *semops;

	ns = task_nsproxy(task)->ipc_ns;
	if (!sem_ids(ns).krgops)
		return ERR_PTR(-EINVAL);

	semops = container_of(sem_ids(ns).krgops, struct semkrgops, krgops);

	/* get a random id */
	undo_list_id = get_unique_id(&semops->undo_list_unique_id_root);

	undo_list = _kddm_grab_object_manual_ft(undo_list_set, undo_list_id);

	BUG_ON(undo_list);

	undo_list = kzalloc(sizeof(struct semundo_list_object), GFP_KERNEL);
	if (!undo_list) {
		undo_list = ERR_PTR(-ENOMEM);
		goto err_alloc;
	}

	undo_list->id = undo_list_id;
	atomic_inc(&undo_list->refcnt);

	_kddm_set_object(undo_list_set, undo_list_id, undo_list);

	task->sysvsem.undo_list_id = undo_list_id;
exit:
	return undo_list;

err_alloc:
	_kddm_put_object(undo_list_set, undo_list_id);
	goto exit;
}

int create_semundo_proc_list(struct task_struct *task)
{
	int r = 0;
	struct kddm_set *undo_list_set;
	struct semundo_list_object *undo_list;

	BUG_ON(task->sysvsem.undo_list_id != UNIQUE_ID_NONE);

	undo_list_set = task_undolist_set(task);
	if (IS_ERR(undo_list_set)) {
		undo_list = ERR_PTR(PTR_ERR(undo_list_set));
		goto err;
	}

	undo_list = __create_semundo_proc_list(task, undo_list_set);

	if (IS_ERR(undo_list)) {
		r = PTR_ERR(undo_list);
		goto err;
	}

	BUG_ON(atomic_read(&undo_list->refcnt) != 1);

	_kddm_put_object(undo_list_set, task->sysvsem.undo_list_id);
err:
	return r;
}


static int __share_new_semundo(struct task_struct *task)
{
	int r = 0;
	struct semundo_list_object *undo_list;
	struct kddm_set *undo_list_set;

	BUG_ON(krg_current);
	BUG_ON(current->sysvsem.undo_list_id != UNIQUE_ID_NONE);

	undo_list_set = task_undolist_set(task);
	if (IS_ERR(undo_list_set)) {
		r = PTR_ERR(undo_list_set);
		goto exit;
	}

	undo_list = __create_semundo_proc_list(current, undo_list_set);

	if (IS_ERR(undo_list)) {
		r = PTR_ERR(undo_list);
		goto exit;
	}

	task->sysvsem.undo_list_id = current->sysvsem.undo_list_id;
	atomic_inc(&undo_list->refcnt);

	BUG_ON(atomic_read(&undo_list->refcnt) != 2);

	_kddm_put_object(undo_list_set, current->sysvsem.undo_list_id);
exit:
	return r;
}

int share_existing_semundo_proc_list(struct task_struct *task,
				     unique_id_t undo_list_id)
{
	int r = 0;
	struct semundo_list_object *undo_list;
	struct kddm_set *undo_list_set;

	undo_list_set = task_undolist_set(task);
	if (IS_ERR(undo_list_set)) {
		r = PTR_ERR(undo_list_set);
		goto exit;
	}

	BUG_ON(undo_list_id == UNIQUE_ID_NONE);

	undo_list = _kddm_grab_object_no_ft(undo_list_set, undo_list_id);

	if (!undo_list) {
		r = -ENOMEM;
		goto exit_put;
	}

	task->sysvsem.undo_list_id = undo_list_id;
	atomic_inc(&undo_list->refcnt);

exit_put:
	_kddm_put_object(undo_list_set, undo_list_id);
exit:
	return r;
}

int krg_ipc_sem_copy_semundo(unsigned long clone_flags,
			     struct task_struct *tsk)
{
	int r = 0;

	BUG_ON(!tsk);

	if (krg_current)
		goto exit;

	if (clone_flags & CLONE_SYSVSEM) {

		/* Do not support fork of process which had used semaphore
		   before Kerrighed was loaded */
		if (current->sysvsem.undo_list) {
			printk("ERROR: Do not support fork of process (%d - %s)"
			       "that had used semaphore before Kerrighed was "
			       "started\n", tsk->tgid, tsk->comm);
			r = -EPERM;
			goto exit;
		}

		if (current->sysvsem.undo_list_id != UNIQUE_ID_NONE)
			r = share_existing_semundo_proc_list(
				tsk, current->sysvsem.undo_list_id);
		else
			r = __share_new_semundo(tsk);

	} else
		/* undolist will be only created when needed */
		tsk->sysvsem.undo_list_id = UNIQUE_ID_NONE;

	/* pointer to undo_list is useless in KRG implementation of semaphores */
	tsk->sysvsem.undo_list = NULL;

exit:
	return r;
}

int add_semundo_to_proc_list(struct semundo_list_object *undo_list, int semid)
{
	struct semundo_id *undo_id;
	int r = 0;
	BUG_ON(!undo_list);

#ifdef CONFIG_KRG_DEBUG
	/* WARNING: this is a paranoiac checking */
	for (undo_id = undo_list->list; undo_id; undo_id = undo_id->next) {
		if (undo_id->semid == semid) {
			printk("%p %p %d %d\n", undo_id,
			       undo_list, semid,
			       atomic_read(&undo_list->semcnt));
			BUG();
		}
	}
#endif

	undo_id = kmalloc(sizeof(struct semundo_id), GFP_KERNEL);
	if (!undo_id) {
		r = -ENOMEM;
		goto exit;
	}

	atomic_inc(&undo_list->semcnt);
	undo_id->semid = semid;
	undo_id->next = undo_list->list;
	undo_list->list = undo_id;
exit:
	return r;
}

struct sem_undo * krg_ipc_sem_find_undo(struct sem_array* sma)
{
	struct sem_undo * undo;
	int r = 0;
	struct kddm_set *undo_list_set;
	struct semundo_list_object *undo_list = NULL;
	unique_id_t undo_list_id;

	undo_list_set = krgipc_ops_undolist_set(sma->sem_perm.krgops);
	if (IS_ERR(undo_list_set)) {
		undo = ERR_PTR(PTR_ERR(undo_list_set));
		goto exit;
	}

	if (current->sysvsem.undo_list_id == UNIQUE_ID_NONE) {

		/* create a undolist if not yet allocated */
		undo_list = __create_semundo_proc_list(current, undo_list_set);

		if (IS_ERR(undo_list)) {
			undo = ERR_PTR(PTR_ERR(undo_list));
			goto exit;
		}

		BUG_ON(atomic_read(&undo_list->semcnt) != 0);

	} else {
		/* check in the undo list of the sma */
		list_for_each_entry(undo, &sma->list_id, list_id) {
			if (undo->proc_list_id ==
			    current->sysvsem.undo_list_id) {
				goto exit;
			}
		}
	}

	undo_list_id = current->sysvsem.undo_list_id;

	/* allocate one */
	undo = kzalloc(sizeof(struct sem_undo) +
		       sizeof(short)*(sma->sem_nsems), GFP_KERNEL);
	if (!undo) {
		undo = ERR_PTR(-ENOMEM);
		goto exit_put_kddm;
	}

	INIT_LIST_HEAD(&undo->list_proc);
	undo->proc_list_id = undo_list_id;
	undo->semid = sma->sem_perm.id;
	undo->semadj = (short *) &undo[1];

	list_add(&undo->list_id, &sma->list_id);

	/* reference it in the undo_list per process*/
	BUG_ON(undo_list_id == UNIQUE_ID_NONE);

	if (!undo_list)
		undo_list = _kddm_grab_object_no_ft(undo_list_set,
						    undo_list_id);

	if (!undo_list) {
		r = -ENOMEM;
		goto exit_free_undo;
	}

	r = add_semundo_to_proc_list(undo_list, undo->semid);

exit_free_undo:
	if (r) {
		list_del(&undo->list_id);
		kfree(undo);
		undo = ERR_PTR(r);
	}

exit_put_kddm:
	if (undo_list && !IS_ERR(undo_list))
		_kddm_put_object(undo_list_set, undo_list_id);
exit:
	return undo;
}

static inline void __remove_semundo_from_sem_list(struct ipc_namespace *ns,
						  int semid,
						  unique_id_t undo_list_id)
{
	struct sem_array *sma;
	struct sem_undo *un, *tu;

	sma = sem_lock(ns, semid);
	if (IS_ERR(sma))
		return;

	list_for_each_entry_safe(un, tu, &sma->list_id, list_id) {
		if (un->proc_list_id == undo_list_id) {
			list_del(&un->list_id);
			__exit_sem_found(sma, un);

			kfree(un);
			goto exit_unlock;
		}
	}
	BUG();

exit_unlock:
	sem_unlock(sma);
}

void krg_ipc_sem_exit_sem(struct ipc_namespace *ns,
			  struct task_struct * task)
{
	struct kddm_set *undo_list_kddm_set;
	unique_id_t undo_list_id;
	struct semundo_list_object * undo_list;
	struct semundo_id * undo_id, *next;

	if (task->sysvsem.undo_list_id == UNIQUE_ID_NONE)
		return;

	undo_list_kddm_set = krgipc_ops_undolist_set(sem_ids(ns).krgops);
	if (IS_ERR(undo_list_kddm_set)) {
		BUG();
		return;
	}

	undo_list_id = task->sysvsem.undo_list_id;

	undo_list = _kddm_grab_object_no_ft(undo_list_kddm_set, undo_list_id);
	if (!undo_list) {
		printk("undo_list_id: %lu\n", undo_list_id);
		BUG();
	}
	if (!atomic_dec_and_test(&undo_list->refcnt))
		goto exit_wo_action;

	for (undo_id = undo_list->list; undo_id; undo_id = next) {
		next = undo_id->next;
		__remove_semundo_from_sem_list(ns, undo_id->semid,
					       undo_list_id);
		kfree(undo_id);
	}
	undo_list->list = NULL;
	atomic_set(&undo_list->semcnt, 0);

	_kddm_remove_frozen_object(undo_list_kddm_set, undo_list_id);

	return;

exit_wo_action:
	_kddm_put_object(undo_list_kddm_set, undo_list_id);
}

/*****************************************************************************/
/*                                                                           */
/*                              INITIALIZATION                               */
/*                                                                           */
/*****************************************************************************/

static int ipc_flusher(struct kddm_set *set, objid_t objid,
		       struct kddm_obj *obj_entry, void *data)
{
	kerrighed_node_t node;

	/*
	 * TODO: choose a better node to flush to.
	 * This may be done looking at the processes blocked.
	 */
	node = first_krgnode(krgnode_online_map);

	return node;
}

int krg_sem_flush_set(struct ipc_namespace *ns)
{
	struct semkrgops *semops;

	down_write(&sem_ids(ns).rw_mutex);

	semops = container_of(sem_ids(ns).krgops, struct semkrgops, krgops);

	_kddm_flush_set(semops->krgops.data_kddm_set, ipc_flusher, NULL);
	_kddm_flush_set(semops->krgops.map_kddm_set, ipc_flusher, NULL);
	_kddm_flush_set(semops->krgops.key_kddm_set, ipc_flusher, NULL);

	_kddm_flush_set(semops->undo_list_kddm_set, ipc_flusher, NULL);

	up_write(&sem_ids(ns).rw_mutex);

	return 0;
}

int krg_sem_init_ns(struct ipc_namespace *ns)
{
	int r;

	struct semkrgops *sem_ops = kmalloc(sizeof(struct semkrgops),
					     GFP_KERNEL);
	if (!sem_ops) {
		r = -ENOMEM;
		goto err;
	}

	sem_ops->krgops.map_kddm_set = create_new_kddm_set(
		kddm_def_ns, SEMMAP_KDDM_ID, IPCMAP_LINKER,
		KDDM_RR_DEF_OWNER, sizeof(ipcmap_object_t),
		KDDM_LOCAL_EXCLUSIVE);

	if (IS_ERR(sem_ops->krgops.map_kddm_set)) {
		r = PTR_ERR(sem_ops->krgops.map_kddm_set);
		goto err_map;
	}

	sem_ops->krgops.key_kddm_set = create_new_kddm_set(
		kddm_def_ns, SEMKEY_KDDM_ID, SEMKEY_LINKER,
		KDDM_RR_DEF_OWNER, sizeof(long), KDDM_LOCAL_EXCLUSIVE);

	if (IS_ERR(sem_ops->krgops.key_kddm_set)) {
		r = PTR_ERR(sem_ops->krgops.key_kddm_set);
		goto err_key;
	}

	sem_ops->krgops.data_kddm_set = create_new_kddm_set(
		kddm_def_ns, SEMARRAY_KDDM_ID, SEMARRAY_LINKER,
		KDDM_RR_DEF_OWNER, sizeof(semarray_object_t),
		KDDM_LOCAL_EXCLUSIVE | KDDM_NEED_SAFE_WALK);

	if (IS_ERR(sem_ops->krgops.data_kddm_set)) {
		r = PTR_ERR(sem_ops->krgops.data_kddm_set);
		goto err_data;
	}

	sem_ops->undo_list_kddm_set = create_new_kddm_set(
		kddm_def_ns, SEMUNDO_KDDM_ID, SEMUNDO_LINKER,
		KDDM_RR_DEF_OWNER, sizeof(struct semundo_list_object),
		KDDM_LOCAL_EXCLUSIVE);

	if (IS_ERR(sem_ops->undo_list_kddm_set)) {
		r = PTR_ERR(sem_ops->undo_list_kddm_set);
		goto err_undolist;
	}

	init_unique_id_root(UNIQUE_ID_SEMUNDO,
			    &sem_ops->undo_list_unique_id_root);

	sem_ops->krgops.ipc_lock = kcb_ipc_sem_lock;
	sem_ops->krgops.ipc_unlock = kcb_ipc_sem_unlock;
	sem_ops->krgops.ipc_findkey = kcb_ipc_sem_findkey;

	sem_ids(ns).krgops = &sem_ops->krgops;

	return 0;

err_undolist:
	_destroy_kddm_set(sem_ops->krgops.data_kddm_set);
err_data:
	_destroy_kddm_set(sem_ops->krgops.key_kddm_set);
err_key:
	_destroy_kddm_set(sem_ops->krgops.map_kddm_set);
err_map:
	kfree(sem_ops);
err:
	return r;
}

void krg_sem_exit_ns(struct ipc_namespace *ns)
{
	if (sem_ids(ns).krgops) {
		struct semkrgops *sem_ops;

		sem_ops = container_of(sem_ids(ns).krgops, struct semkrgops,
				      krgops);

		unregister_unique_id_root(UNIQUE_ID_SEMUNDO);

		_destroy_kddm_set(sem_ops->undo_list_kddm_set);
		_destroy_kddm_set(sem_ops->krgops.data_kddm_set);
		_destroy_kddm_set(sem_ops->krgops.key_kddm_set);
		_destroy_kddm_set(sem_ops->krgops.map_kddm_set);

		kfree(sem_ops);
	}
}

void sem_handler_init (void)
{
	semarray_object_cachep = kmem_cache_create("semarray_object",
						   sizeof(semarray_object_t),
						   0, SLAB_PANIC, NULL);

	register_io_linker(SEMARRAY_LINKER, &semarray_linker);
	register_io_linker(SEMKEY_LINKER, &semkey_linker);
	register_io_linker(SEMUNDO_LINKER, &semundo_linker);

	rpc_register_void(IPC_SEM_WAKEUP, handle_ipcsem_wakeup_process, 0);
}



void sem_handler_finalize (void)
{
}
