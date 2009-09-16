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
#include <linux/nsproxy.h>
#include <kddm/kddm.h>
#include <net/krgrpc/rpc.h>
#include <kerrighed/hotplug.h>
#include "ipc_handler.h"
#include "sem_handler.h"
#include "semarray_io_linker.h"
#include "semundolst_io_linker.h"
#include "ipcmap_io_linker.h"
#include "util.h"
#include "krgsem.h"

/* Kddm set of SEM array structures */
struct kddm_set *semarray_struct_kddm_set = NULL;
struct kddm_set *semkey_struct_kddm_set = NULL;

/* Kddm set of sem_undo_list */
struct kddm_set *sem_undo_list_kddm_set = NULL;

/* unique_id generator for sem_undo_list identifier */
unique_id_root_t undo_list_unique_id_root;

/* Kddm set of IPC allocation bitmap structures */
struct kddm_set *semmap_struct_kddm_set = NULL;

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

	rcu_read_lock();

	index = ipcid_to_idx(id);

	sem_object = _kddm_grab_object_no_ft(semarray_struct_kddm_set, index);

	if (!sem_object)
		goto error;

	sma = sem_object->local_sem;

	BUG_ON(!sma);

	mutex_lock(&sma->sem_perm.mutex);

	if (sma->sem_perm.deleted) {
		mutex_unlock(&sma->sem_perm.mutex);
		goto error;
	}

	return &(sma->sem_perm);

error:
	_kddm_put_object(semarray_struct_kddm_set, index);
	rcu_read_unlock();

	return ERR_PTR(-EINVAL);
}

void kcb_ipc_sem_unlock(struct kern_ipc_perm *ipcp)
{
	int index, deleted = 0;

	index = ipcid_to_idx(ipcp->id);

	if (ipcp->deleted)
		deleted = 1;

	_kddm_put_object(semarray_struct_kddm_set, index);

	if (!deleted)
		mutex_unlock(&ipcp->mutex);

	rcu_read_unlock();
}

struct kern_ipc_perm *kcb_ipc_sem_findkey(struct ipc_ids *ids, key_t key)
{
	long *key_index;
	int id = -1;

	key_index = _kddm_get_object_no_ft(semkey_struct_kddm_set, key);

	if (key_index)
		id = *key_index;

	_kddm_put_object(semkey_struct_kddm_set, key);

	if (id != -1)
		return kcb_ipc_sem_lock(ids, id);

	return NULL;
}

/** Notify the creation of a new IPC sem_array to Kerrighed.
 *
 *  @author Matthieu Fertré
 */
int kcb_ipc_sem_newary(struct ipc_namespace *ns, struct sem_array *sma)
{
	semarray_object_t *sem_object;
	long *key_index;
	int index ;

	BUG_ON(!sem_ids(ns).krgops);

	index = ipcid_to_idx(sma->sem_perm.id);

	sem_object = _kddm_grab_object_manual_ft(semarray_struct_kddm_set,
						 index);

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

	_kddm_set_object(semarray_struct_kddm_set, index, sem_object);

	if (sma->sem_perm.key != IPC_PRIVATE)
	{
		key_index = _kddm_grab_object(semkey_struct_kddm_set,
					      sma->sem_perm.key);
		*key_index = index;
		_kddm_put_object (semkey_struct_kddm_set, sma->sem_perm.key);
	}

	_kddm_put_object(semarray_struct_kddm_set, index);

	sma->sem_perm.krgops = sem_ids(ns).krgops;

	return 0;
}

static inline void __remove_semundo_from_proc_list(struct sem_array *sma,
						   unique_id_t proc_list_id)
{
	struct semundo_id * undo_id, *next, *prev;
	semundo_list_object_t *undo_list = _kddm_grab_object_no_ft(
		sem_undo_list_kddm_set,	proc_list_id);

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
	_kddm_put_object(sem_undo_list_kddm_set, proc_list_id);
}

void kcb_ipc_sem_freeary(struct ipc_namespace *ns, struct sem_array *sma, int id)
{
	int index;
	key_t key;
	struct sem_undo* un, *tu;

	index = ipcid_to_idx(sma->sem_perm.id);
	key = sma->sem_perm.key;

	/* removing the related semundo from the list per process */
	list_for_each_entry_safe(un, tu, &sma->list_id, list_id) {
		list_del(&un->list_id);
		__remove_semundo_from_proc_list(sma, un->proc_list_id);
		kfree(un);
	}

	if (key != IPC_PRIVATE) {
		_kddm_grab_object(semkey_struct_kddm_set,
				  sma->sem_perm.key);
		_kddm_remove_frozen_object (semkey_struct_kddm_set, key);
		/* _kddm_remove_object (semkey_struct_kddm_set, key); */
	}

	local_sem_unlock(sma);
	_kddm_remove_frozen_object (semarray_struct_kddm_set, index);

	kh_ipc_rmid(&sem_ids(ns), index);
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
	struct ipc_namespace *ns = &init_ipc_ns; /* TODO: manage IPC namespace */

	/* take only a local lock because the requester node has the kddm lock
	   on the semarray */
	sma = local_sem_lock(ns, msg->sem_id);
	BUG_ON(!sma);

	list_for_each_entry_safe(q, tq, &sma->sem_pending, list) {
		/* compare to q->sleeper->pid instead of q->pid
		   because q->pid == q->sleeper->tgid */
		if (q->sleeper->pid == msg->pid) {
			list_del(&q->list);
			goto found;
		}
	}

	BUG();
found:
	q->status = 1; /* IN_WAKEUP; */

	BUG_ON(!q->sleeper);
	BUG_ON(q->pid != q->sleeper->tgid);

	wake_up_process(q->sleeper);
	smp_wmb();
	q->status = msg->error;

	local_sem_unlock(sma);

	rpc_pack_type(desc, msg->error);
}

void kcb_ipc_sem_wakeup_process(struct sem_queue *q, int error)
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


static inline semundo_list_object_t * __create_semundo_proc_list(unique_id_t * undo_list_id)
{
	semundo_list_object_t *undo_list;

	/* get a random id */
	*undo_list_id = get_unique_id(&undo_list_unique_id_root);

	undo_list = _kddm_grab_object_manual_ft(
		sem_undo_list_kddm_set,
		*undo_list_id);

	BUG_ON(undo_list);

	undo_list = kzalloc(sizeof(semundo_list_object_t), GFP_KERNEL);
	if (!undo_list) {
		undo_list = ERR_PTR(-ENOMEM);
		goto exit;
	}

	undo_list->id = *undo_list_id;
	atomic_inc(&undo_list->refcnt);

	_kddm_set_object(sem_undo_list_kddm_set, *undo_list_id, undo_list);
exit:
	return undo_list;
}

int create_semundo_proc_list(struct task_struct *tsk)
{
	int r = 0;
	semundo_list_object_t *undo_list;

	BUG_ON(tsk->sysvsem.undo_list_id != UNIQUE_ID_NONE);
	undo_list = __create_semundo_proc_list(
		&tsk->sysvsem.undo_list_id);

	if (IS_ERR(undo_list)) {
		r = PTR_ERR(undo_list);
		goto exit;
	}

	BUG_ON(atomic_read(&undo_list->refcnt) != 1);

exit:
	_kddm_put_object(sem_undo_list_kddm_set,
			 tsk->sysvsem.undo_list_id);
	return r;
}


static int __share_new_semundo(struct task_struct *tsk)
{
	int r = 0;
	semundo_list_object_t *undo_list;

	/* TODO BUG_ON(krg_current);*/
	BUG_ON(current->sysvsem.undo_list_id != UNIQUE_ID_NONE);

	undo_list = __create_semundo_proc_list(
		&current->sysvsem.undo_list_id);

	if (IS_ERR(undo_list)) {
		r = PTR_ERR(undo_list);
		goto exit;
	}

	tsk->sysvsem.undo_list_id = current->sysvsem.undo_list_id;
	atomic_inc(&undo_list->refcnt);

	BUG_ON(atomic_read(&undo_list->refcnt) != 2);

	_kddm_put_object(sem_undo_list_kddm_set,
			 current->sysvsem.undo_list_id);
exit:
	return r;
}

int share_existing_semundo_proc_list(struct task_struct *tsk,
				     unique_id_t undo_list_id)
{
	int r = 0;
	semundo_list_object_t *undo_list;

	BUG_ON(undo_list_id == UNIQUE_ID_NONE);

	undo_list = _kddm_grab_object_no_ft(sem_undo_list_kddm_set,
					    undo_list_id);

	if (!undo_list) {
		r = -ENOMEM;
		goto exit;
	}

	tsk->sysvsem.undo_list_id = undo_list_id;
	atomic_inc(&undo_list->refcnt);

exit:
	_kddm_put_object(sem_undo_list_kddm_set,
			 undo_list_id);
	return r;
}

int kcb_ipc_sem_copy_semundo(unsigned long clone_flags,
			    struct task_struct *tsk)
{
	int r = 0;

	BUG_ON(!tsk);

	/* TODO
	 * if (krg_current)
	 *	goto exit;
	 */

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

static inline int __add_semundo_to_proc_list(semundo_list_object_t *undo_list,
					     int semid)
{
	struct semundo_id * undo_id;
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

struct sem_undo * kcb_ipc_sem_find_undo(struct sem_array* sma)
{
	struct sem_undo * undo;
	int r = 0;
	semundo_list_object_t *undo_list = NULL;
	unique_id_t undo_list_id = current->sysvsem.undo_list_id;

	if (undo_list_id == UNIQUE_ID_NONE) {
		/* create a undolist if not yet allocated */
		undo_list = __create_semundo_proc_list(
			&undo_list_id);

		if (IS_ERR(undo_list)) {
			undo = ERR_PTR(PTR_ERR(undo_list));
			goto exit;
		}

		BUG_ON(atomic_read(&undo_list->semcnt) != 0);

		current->sysvsem.undo_list_id = undo_list_id;
	} else {
		/* check in the undo list of the sma */
		list_for_each_entry(undo, &sma->list_id, list_id) {
			if (undo->proc_list_id == undo_list_id) {
				goto exit;
			}
		}
	}

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
		undo_list = _kddm_grab_object_no_ft(sem_undo_list_kddm_set,
						    undo_list_id);

	if (!undo_list) {
		r = -ENOMEM;
		goto exit_free_undo;
	}

	r = __add_semundo_to_proc_list(undo_list, undo->semid);

exit_free_undo:
	if (r) {
		list_del(&undo->list_id);
		kfree(undo);
		undo = ERR_PTR(r);
	}

exit_put_kddm:
	if (undo_list && !IS_ERR(undo_list))
		_kddm_put_object(sem_undo_list_kddm_set,
				 undo_list_id);
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
	if (!sma)
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

void leave_semundo_proc_list(unique_id_t undo_list_id)
{
	semundo_list_object_t * undo_list;
	struct semundo_id * undo_id, *next;

	BUG_ON(undo_list_id == UNIQUE_ID_NONE);

	undo_list = _kddm_grab_object_no_ft(sem_undo_list_kddm_set,
					    undo_list_id);
	if (!undo_list) {
		printk("undo_list_id: %lu\n", undo_list_id);
		BUG();
	}
	if (!atomic_dec_and_test(&undo_list->refcnt))
		goto exit_wo_action;

	for (undo_id = undo_list->list; undo_id; undo_id = next) {
		next = undo_id->next;
		__remove_semundo_from_sem_list(&init_ipc_ns, undo_id->semid,
					       undo_list_id);
		kfree(undo_id);
	}
	undo_list->list = NULL;
	atomic_set(&undo_list->semcnt, 0);

	_kddm_remove_frozen_object(sem_undo_list_kddm_set,
				   undo_list_id);

	return;

exit_wo_action:
	_kddm_put_object(sem_undo_list_kddm_set,
			 undo_list_id);
}

void kcb_ipc_sem_exit_sem(struct task_struct * tsk)
{
	if (tsk->sysvsem.undo_list_id == UNIQUE_ID_NONE)
		return;

	leave_semundo_proc_list(tsk->sysvsem.undo_list_id);
}

/*****************************************************************************/
/*                                                                           */
/*                              INITIALIZATION                               */
/*                                                                           */
/*****************************************************************************/

void krg_sem_init_ns(struct ipc_namespace *ns)
{
	struct krgipc_ops *sem_ops = kmalloc(sizeof(struct krgipc_ops),
					     GFP_KERNEL);

	sem_ops->map_kddm = SEMMAP_KDDM_ID;
	sem_ops->key_kddm = SEMKEY_KDDM_ID;
	sem_ops->data_kddm = SEMARRAY_KDDM_ID;

	sem_ops->ipc_lock = kcb_ipc_sem_lock;
	sem_ops->ipc_unlock = kcb_ipc_sem_unlock;
	sem_ops->ipc_findkey = kcb_ipc_sem_findkey;

	sem_ids(ns).krgops = sem_ops;
}

void krg_sem_exit_ns(struct ipc_namespace *ns)
{
	if (sem_ids(ns).krgops)
		kfree(sem_ids(ns).krgops);
}

void sem_handler_init (void)
{
	init_unique_id_root(&undo_list_unique_id_root);

	semarray_object_cachep = kmem_cache_create("semarray_object",
						   sizeof(semarray_object_t),
						   0, SLAB_PANIC, NULL);

	register_io_linker(SEMARRAY_LINKER, &semarray_linker);
	register_io_linker(SEMKEY_LINKER, &semkey_linker);
	register_io_linker(SEMUNDO_LINKER, &semundo_linker);

	semarray_struct_kddm_set = create_new_kddm_set(kddm_def_ns,
						       SEMARRAY_KDDM_ID,
						       SEMARRAY_LINKER,
						       KDDM_RR_DEF_OWNER,
						       sizeof(semarray_object_t),
						       KDDM_LOCAL_EXCLUSIVE);

	BUG_ON (IS_ERR (semarray_struct_kddm_set));

	semkey_struct_kddm_set = create_new_kddm_set (kddm_def_ns,
						      SEMKEY_KDDM_ID,
						      SEMKEY_LINKER,
						      KDDM_RR_DEF_OWNER,
						      sizeof(long), 0);

	BUG_ON (IS_ERR (semkey_struct_kddm_set));

	semmap_struct_kddm_set = create_new_kddm_set (kddm_def_ns,
						      SEMMAP_KDDM_ID,
						      IPCMAP_LINKER,
						      KDDM_RR_DEF_OWNER,
						      sizeof(ipcmap_object_t),
						      KDDM_LOCAL_EXCLUSIVE);

	BUG_ON (IS_ERR (semmap_struct_kddm_set));

	sem_undo_list_kddm_set = create_new_kddm_set (kddm_def_ns,
						      SEMUNDO_KDDM_ID,
						      SEMUNDO_LINKER,
						      KDDM_RR_DEF_OWNER,
						      sizeof(semundo_list_object_t),
						      KDDM_LOCAL_EXCLUSIVE);

	krg_sem_init_ns(&init_ipc_ns);

	hook_register(&kh_ipc_sem_newary, kcb_ipc_sem_newary);
	hook_register(&kh_ipc_sem_freeary, kcb_ipc_sem_freeary);
	hook_register(&kh_ipc_sem_wakeup_process, kcb_ipc_sem_wakeup_process);
	hook_register(&kh_ipc_sem_copy_semundo, kcb_ipc_sem_copy_semundo);
	hook_register(&kh_ipc_sem_find_undo, kcb_ipc_sem_find_undo);
	hook_register(&kh_ipc_sem_exit_sem, kcb_ipc_sem_exit_sem);

	rpc_register_void(IPC_SEM_WAKEUP, handle_ipcsem_wakeup_process, 0);
}



void sem_handler_finalize (void)
{
}
