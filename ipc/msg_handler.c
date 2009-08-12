/** All the code for IPC messages accross the cluster
 *  @file msg_handler.c
 *
 *  Copyright (C) 2001-2006, INRIA, Universite de Rennes 1, EDF.
 *  Copyright (C) 2007-2008 Matthieu Fertré - INRIA
 */

#ifndef NO_MSG

#include <linux/ipc.h>
#include <linux/ipc_namespace.h>
#include <linux/msg.h>
#include <linux/syscalls.h>

#include <kddm/kddm.h>
#include <net/krgrpc/rpc.h>
#include <kerrighed/hotplug.h>
#include "ipc_handler.h"
#include "msg_handler.h"
#include "msg_io_linker.h"
#include "ipcmap_io_linker.h"
#include "util.h"
#include "krgmsg.h"

struct msgkrgops {
	struct krgipc_ops krgops;
	struct kddm_set *master_kddm_set;
};

static struct kddm_set *krgipc_ops_master_set(struct krgipc_ops *ipcops)
{
	struct msgkrgops *msgops;

	msgops = container_of(ipcops, struct msgkrgops, krgops);

	return msgops->master_kddm_set;
}

/*****************************************************************************/
/*                                                                           */
/*                                KERNEL HOOKS                               */
/*                                                                           */
/*****************************************************************************/

struct kern_ipc_perm *kcb_ipc_msg_lock(struct ipc_ids *ids, int id)
{
	msq_object_t *msq_object;
	struct msg_queue *msq;
	int index;

	rcu_read_lock();

	index = ipcid_to_idx(id);

	msq_object = _kddm_grab_object_no_ft(ids->krgops->data_kddm_set, index);

	if (!msq_object)
		goto error;

	msq = msq_object->local_msq;

	BUG_ON(!msq);

	mutex_lock(&msq->q_perm.mutex);

	if (msq->q_perm.deleted) {
		mutex_unlock(&msq->q_perm.mutex);
		goto error;
	}

	return &(msq->q_perm);

error:
	_kddm_put_object(ids->krgops->data_kddm_set, index);
	rcu_read_unlock();

	return ERR_PTR(-EINVAL);
}

void kcb_ipc_msg_unlock(struct kern_ipc_perm *ipcp)
{
	int index, deleted = 0;

	index = ipcid_to_idx(ipcp->id);

	if (ipcp->deleted)
		deleted = 1;

	_kddm_put_object(ipcp->krgops->data_kddm_set, index);

	if (!deleted)
		mutex_unlock(&ipcp->mutex);

	rcu_read_unlock();
}

struct kern_ipc_perm *kcb_ipc_msg_findkey(struct ipc_ids *ids, key_t key)
{
	long *key_index;
	int id = -1;

	key_index = _kddm_get_object_no_ft(ids->krgops->key_kddm_set, key);

	if (key_index)
		id = *key_index;

	_kddm_put_object(ids->krgops->key_kddm_set, key);

	if (id != -1)
		return kcb_ipc_msg_lock(ids, id);

	return NULL;
}

/** Notify the creation of a new IPC msg queue to Kerrighed.
 *
 *  @author Matthieu Fertré
 */
int kcb_ipc_msg_newque(struct ipc_namespace *ns, struct msg_queue *msq)
{
	struct kddm_set *master_set;
	msq_object_t *msq_object;
	kerrighed_node_t *master_node;
	long *key_index;
	int index, err = 0;

	BUG_ON(!msg_ids(ns).krgops);

	index = ipcid_to_idx(msq->q_perm.id);

	msq_object = _kddm_grab_object_manual_ft(
		msg_ids(ns).krgops->data_kddm_set, index);

	BUG_ON(msq_object);

	msq_object = kmem_cache_alloc(msq_object_cachep, GFP_KERNEL);
	if (!msq_object) {
		err = -ENOMEM;
		goto err_put;
	}

	msq_object->local_msq = msq;
	msq_object->local_msq->is_master = 1;
	msq_object->mobile_msq.q_perm.id = -1;

	_kddm_set_object(msg_ids(ns).krgops->data_kddm_set, index, msq_object);

	if (msq->q_perm.key != IPC_PRIVATE)
	{
		key_index = _kddm_grab_object(msg_ids(ns).krgops->key_kddm_set,
					      msq->q_perm.key);
		*key_index = index;
		_kddm_put_object(msg_ids(ns).krgops->key_kddm_set,
				 msq->q_perm.key);
	}

	master_set = krgipc_ops_master_set(msg_ids(ns).krgops);

	master_node = _kddm_grab_object(master_set, index);
	*master_node = kerrighed_node_id;

	msq->q_perm.krgops = msg_ids(ns).krgops;

	_kddm_put_object(master_set, index);

err_put:
	_kddm_put_object(msg_ids(ns).krgops->data_kddm_set, index);

	return err;
}

void kcb_ipc_msg_freeque(struct ipc_namespace *ns, struct kern_ipc_perm *ipcp)
{
	int index;
	key_t key;
	struct kddm_set *master_set;
	struct msg_queue *msq = container_of(ipcp, struct msg_queue, q_perm);

	index = ipcid_to_idx(msq->q_perm.id);
	key = msq->q_perm.key;

	if (key != IPC_PRIVATE) {
		_kddm_grab_object_no_ft(ipcp->krgops->key_kddm_set, key);
		_kddm_remove_frozen_object(ipcp->krgops->key_kddm_set, key);
	}

	master_set = krgipc_ops_master_set(ipcp->krgops);

	_kddm_grab_object_no_ft(master_set, index);
	_kddm_remove_frozen_object(master_set, index);

	local_msg_unlock(msq);

	_kddm_remove_frozen_object(ipcp->krgops->data_kddm_set, index);

	kh_ipc_rmid(&msg_ids(ns), index);
}

/*****************************************************************************/

struct msgsnd_msg
{
	kerrighed_node_t requester;
	int msqid;
	long mtype;
	int msgflg;
	pid_t tgid;
};

long kcb_ipc_msgsnd(int msqid, long mtype, void __user *mtext,
		    size_t msgsz, int msgflg, struct ipc_namespace *ns,
		    pid_t tgid)
{
	struct rpc_desc * desc;
	struct kddm_set *master_set;
	kerrighed_node_t* master_node;
	void *buffer;
	long r;
	enum rpc_error err;
	int index;
	struct msgsnd_msg msg;

	msg.requester = kerrighed_node_id;
	msg.msqid = msqid;
	msg.mtype = mtype;
	msg.msgflg = msgflg;
	msg.tgid = tgid;

	buffer = kmalloc(msgsz, GFP_KERNEL);
	r = copy_from_user(buffer, mtext, msgsz);
	if (r)
		goto exit;

	/* TODO: manage ipc namespace */
	index = ipcid_to_idx(msqid);

	master_set = krgipc_ops_master_set(msg_ids(ns).krgops);

	master_node = _kddm_get_object_no_ft(master_set, index);
	if (!master_node) {
		_kddm_put_object(master_set, index);
		r = -EINVAL;
		goto exit;
	}

	if (*master_node == kerrighed_node_id) {
		/* inverting the following 2 lines can conduct to deadlock
		 * if the send is blocked */
		_kddm_put_object(master_set, index);
		r = __do_msgsnd(msqid, mtype, mtext, msgsz,
				msgflg, ns, tgid);
		goto exit;
	}

	desc = rpc_begin(IPC_MSG_SEND, *master_node);
	_kddm_put_object(master_set, index);

	rpc_pack_type(desc, msg);
	rpc_pack_type(desc, msgsz);
	rpc_pack(desc, 0, buffer, msgsz);

	err = rpc_unpack(desc, RPC_FLAGS_INTR, &r, sizeof(r));
	if (err == RPC_EINTR) {
		rpc_signal(desc, next_signal(&current->pending,
					     &current->blocked));
		r = -EINTR;
	}

	rpc_end(desc, 0);

exit:
	kfree(buffer);
	return r;
}

static void handle_do_msg_send(struct rpc_desc *desc, void *_msg, size_t size)
{
	size_t msgsz;
	void *mtext;
	long r;
	sigset_t sigset, oldsigset;
	struct msgsnd_msg *msg = _msg;
	struct ipc_namespace *ns;

	ns = find_get_krg_ipcns();
	BUG_ON(!ns);

	rpc_unpack_type(desc, msgsz);

	mtext = kmalloc(msgsz, GFP_KERNEL);

	rpc_unpack(desc, 0, mtext, msgsz);

	sigfillset(&sigset);
	sigprocmask(SIG_UNBLOCK, &sigset, &oldsigset);

	r = __do_msgsnd(msg->msqid, msg->mtype, mtext, msgsz, msg->msgflg,
			ns, msg->tgid);

	sigprocmask(SIG_SETMASK, &oldsigset, NULL);
	flush_signals(current);

	rpc_pack_type(desc, r);

	kfree(mtext);

	put_ipc_ns(ns);
}

struct msgrcv_msg
{
	kerrighed_node_t requester;
	int msqid;
	long msgtyp;
	int msgflg;
	pid_t tgid;
};

long kcb_ipc_msgrcv(int msqid, long *pmtype, void __user *mtext,
		    size_t msgsz, long msgtyp, int msgflg,
		    struct ipc_namespace *ns, pid_t tgid)
{
	struct rpc_desc * desc;
	enum rpc_error err;
	struct kddm_set *master_set;
	kerrighed_node_t *master_node;
	void * buffer;
	long r;
	int retval;
	int index;
	struct msgrcv_msg msg;
	msg.requester = kerrighed_node_id;
	msg.msqid = msqid;
	msg.msgtyp = msgtyp;
	msg.msgflg = msgflg;
	msg.tgid = tgid;

	/* TODO: manage ipc namespace */
	index = ipcid_to_idx(msqid);

	master_set = krgipc_ops_master_set(msg_ids(ns).krgops);

	master_node = _kddm_get_object_no_ft(master_set, index);
	if (!master_node) {
		_kddm_put_object(master_set, index);
		return -EINVAL;
	}

	if (*master_node == kerrighed_node_id) {
		/*inverting the following 2 lines can conduct to deadlock
		 * if the receive is blocked */
		_kddm_put_object(master_set, index);
		r = __do_msgrcv(msqid, pmtype, mtext, msgsz, msgtyp,
				msgflg, ns, tgid);
		return r;
	}

	desc = rpc_begin(IPC_MSG_RCV, *master_node);
	_kddm_put_object(master_set, index);

	rpc_pack_type(desc, msg);
	rpc_pack_type(desc, msgsz);

	err = rpc_unpack(desc, RPC_FLAGS_INTR, &r, sizeof(r));
	if (!err) {
		if (r > 0) {
			/* get the real msg type */
			rpc_unpack(desc, 0, pmtype, sizeof(long));

			buffer = kmalloc(r, GFP_KERNEL);
			rpc_unpack(desc, 0, buffer, r);
			retval = copy_to_user(mtext, buffer, r);
			kfree(buffer);
			if (retval)
				r = retval;
		}
	} else if (err == RPC_EINTR) {
		/* If we have been interrupted by a signal, we forward it
		   to the rpc handler */
		rpc_signal(desc, next_signal(&current->pending,
				     &current->blocked));
		r = -EINTR;
	}

	rpc_end(desc, 0);
	return r;
}

static void handle_do_msg_rcv(struct rpc_desc *desc, void *_msg, size_t size)
{
	size_t msgsz;
	void *mtext;
	long r;
	long pmtype;
	struct msgrcv_msg *msg = _msg;
	sigset_t sigset, oldsigset;
	struct ipc_namespace *ns;

	ns = find_get_krg_ipcns();
	BUG_ON(!ns);

	rpc_unpack_type(desc, msgsz);

	mtext = kmalloc(msgsz, GFP_KERNEL);

	sigfillset(&sigset);
	sigprocmask(SIG_UNBLOCK, &sigset, &oldsigset);

	r = __do_msgrcv(msg->msqid, &pmtype, mtext, msgsz,
			msg->msgtyp, msg->msgflg, ns, msg->tgid);

	sigprocmask(SIG_SETMASK, &oldsigset, NULL);
	flush_signals(current);

	rpc_pack_type(desc, r);
	if (r > 0) {
		rpc_pack_type(desc, pmtype); /* send the real type of msg */
		rpc_pack(desc, 0, mtext, r);
	}

	kfree(mtext);

	put_ipc_ns(ns);
}


/*****************************************************************************/
/*                                                                           */
/*                              INITIALIZATION                               */
/*                                                                           */
/*****************************************************************************/

int krg_msg_init_ns(struct ipc_namespace *ns)
{
	int r;

	struct msgkrgops *msg_ops = kmalloc(sizeof(struct msgkrgops),
					    GFP_KERNEL);
	if (!msg_ops) {
		r = -ENOMEM;
		goto err;
	}

	msg_ops->krgops.map_kddm_set = create_new_kddm_set(
		kddm_def_ns, MSGMAP_KDDM_ID, IPCMAP_LINKER,
		KDDM_RR_DEF_OWNER, sizeof(ipcmap_object_t),
		KDDM_LOCAL_EXCLUSIVE);

	if (IS_ERR(msg_ops->krgops.map_kddm_set)) {
		r = PTR_ERR(msg_ops->krgops.map_kddm_set);
		goto err_map;
	}

	msg_ops->krgops.key_kddm_set = create_new_kddm_set(
		kddm_def_ns, MSGKEY_KDDM_ID, MSGKEY_LINKER,
		KDDM_RR_DEF_OWNER, sizeof(long),
		KDDM_LOCAL_EXCLUSIVE);

	if (IS_ERR(msg_ops->krgops.key_kddm_set)) {
		r = PTR_ERR(msg_ops->krgops.key_kddm_set);
		goto err_key;
	}

	msg_ops->krgops.data_kddm_set = create_new_kddm_set(
		kddm_def_ns, MSG_KDDM_ID, MSG_LINKER,
		KDDM_RR_DEF_OWNER, sizeof(msq_object_t),
		KDDM_LOCAL_EXCLUSIVE);

	if (IS_ERR(msg_ops->krgops.data_kddm_set)) {
		r = PTR_ERR(msg_ops->krgops.data_kddm_set);
		goto err_data;
	}

	msg_ops->master_kddm_set = create_new_kddm_set(
		kddm_def_ns, MSGMASTER_KDDM_ID, MSGMASTER_LINKER,
		KDDM_RR_DEF_OWNER, sizeof(kerrighed_node_t),
		KDDM_LOCAL_EXCLUSIVE);

	if (IS_ERR(msg_ops->master_kddm_set)) {
		r = PTR_ERR(msg_ops->master_kddm_set);
		goto err_master;
	}

	msg_ops->krgops.ipc_lock = kcb_ipc_msg_lock;
	msg_ops->krgops.ipc_unlock = kcb_ipc_msg_unlock;
	msg_ops->krgops.ipc_findkey = kcb_ipc_msg_findkey;

	msg_ids(ns).krgops = &msg_ops->krgops;

	return 0;

err_master:
	_destroy_kddm_set(msg_ops->krgops.data_kddm_set);
err_data:
	_destroy_kddm_set(msg_ops->krgops.key_kddm_set);
err_key:
	_destroy_kddm_set(msg_ops->krgops.map_kddm_set);
err_map:
	kfree(msg_ops);
err:
	return r;
}

void krg_msg_exit_ns(struct ipc_namespace *ns)
{
	if (msg_ids(ns).krgops) {
		struct msgkrgops *msg_ops;

		msg_ops = container_of(msg_ids(ns).krgops, struct msgkrgops,
				       krgops);

		_destroy_kddm_set(msg_ops->krgops.map_kddm_set);
		_destroy_kddm_set(msg_ops->krgops.key_kddm_set);
		_destroy_kddm_set(msg_ops->krgops.data_kddm_set);
		_destroy_kddm_set(msg_ops->master_kddm_set);

		kfree(msg_ops);
	}
}

void msg_handler_init(void)
{
	msq_object_cachep = kmem_cache_create("msg_queue_object",
					      sizeof(msq_object_t),
					      0, SLAB_PANIC, NULL);

	register_io_linker(MSG_LINKER, &msq_linker);
	register_io_linker(MSGKEY_LINKER, &msqkey_linker);
	register_io_linker(MSGMASTER_LINKER, &msqmaster_linker);

	hook_register(&kh_ipc_msg_newque, kcb_ipc_msg_newque);
	hook_register(&kh_ipc_msg_freeque, kcb_ipc_msg_freeque);
	hook_register(&kh_ipc_msgsnd, kcb_ipc_msgsnd);
	hook_register(&kh_ipc_msgrcv, kcb_ipc_msgrcv);

	rpc_register_void(IPC_MSG_SEND, handle_do_msg_send, 0);
	rpc_register_void(IPC_MSG_RCV, handle_do_msg_rcv, 0);
}



void msg_handler_finalize(void)
{
}

#endif
