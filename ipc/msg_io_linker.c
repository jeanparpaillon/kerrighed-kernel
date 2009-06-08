/*
 *  Kerrighed/modules/ipc/msg_io_linker.c
 *
 *  KDDM IPC msg_queue id Linker.
 *
 *  Copyright (C) 2007-2008 Matthieu Fertré - INRIA
 */
#include <linux/shm.h>
#include <linux/lockdep.h>
#include <linux/security.h>
#include <linux/ipc_namespace.h>
#include <linux/ipc.h>
#include <net/krgrpc/rpc.h>
#include <kddm/kddm.h>

#include "ipc_handler.h"
#include "msg_io_linker.h"
#include "util.h"
#include "krgmsg.h"

#define MODULE_NAME "IPC Msg IO"
#include "debug_keripc.h"

struct kmem_cache *msq_object_cachep;

/** Create a local instance of a remotly existing IPC message queue.
 *
 *  @author Matthieu Fertré
 */
static struct msg_queue *create_local_msq(struct ipc_namespace *ns,
					  struct msg_queue *received_msq)
{
	struct msg_queue *msq;
	int retval;

	IPCDEBUG(DBG_KERIPC_MSG_LINKER, 3, "Create local msgqueue - id %d\n",
	      received_msq->q_perm.id);

	msq = ipc_rcu_alloc(sizeof(*msq));
	if (!msq)
		return ERR_PTR(-ENOMEM);

	IPCDEBUG(DBG_KERIPC_MSG_LINKER, 5, "memory allocated for  local msgqueue %d\n",
	      received_msq->q_perm.id);

	*msq = *received_msq;
	retval = security_msg_queue_alloc(msq);
	if (retval)
		goto err_putref;

	IPCDEBUG(DBG_KERIPC_MSG_LINKER, 5, "reserving id %d...\n",
	      received_msq->q_perm.id);

	/*
	 * ipc_reserveid() locks msq
	 */
	retval = local_ipc_reserveid(&msg_ids(ns), &msq->q_perm, ns->msg_ctlmni);
	if (retval)
		goto err_security_free;

	msq->is_master = 0;
	INIT_LIST_HEAD(&msq->q_messages);
	INIT_LIST_HEAD(&msq->q_receivers);
	INIT_LIST_HEAD(&msq->q_senders);

	msq->q_perm.krgops = msg_ids(ns).krgops;
	local_msg_unlock(msq);

	IPCDEBUG(DBG_KERIPC_MSG_LINKER, 3, "Local msg queue created %d (%p)\n",
	      msq->q_perm.id, msq);

	return msq;

err_security_free:
	security_msg_queue_free(msq);
err_putref:
	ipc_rcu_putref(msq);

	IPCDEBUG(DBG_KERIPC_MSG_LINKER, 1, "Local creation of msg queue %d failed: %d\n",
	      received_msq->q_perm.id, retval);

	return ERR_PTR(retval);
}

/** Remove a local instance of a removed IPC message queue.
 *
 *  @author Matthieu Fertré
 */
static void delete_local_msq(struct ipc_namespace *ns, struct msg_queue *local_msq)
{
	struct msg_queue *msq;

	msq = local_msq;

	security_msg_queue_free(msq);

	ipc_rmid(&msg_ids(ns), &msq->q_perm);

	local_msg_unlock(msq);

	ipc_rcu_putref(msq);
}

/** Update a local instance of a remotly existing IPC message queue.
 *
 *  @author Matthieu Fertré
 */
static void update_local_msq (struct msg_queue *local_msq,
			      struct msg_queue *received_msq)
{
	/* local_msq->q_perm = received_msq->q_perm;*/
	local_msq->q_stime = received_msq->q_stime;
	local_msq->q_rtime = received_msq->q_rtime;
	local_msq->q_ctime = received_msq->q_ctime;
	local_msq->q_cbytes = received_msq->q_cbytes;
	local_msq->q_qnum = received_msq->q_qnum;
	local_msq->q_qbytes = received_msq->q_qbytes;
	local_msq->q_lspid = received_msq->q_lspid;
	local_msq->q_lrpid = received_msq->q_lrpid;

	/* Do not modify the list_head else you will loose
	   information on master node */
}

/*****************************************************************************/
/*                                                                           */
/*                         MSQID KDDM IO FUNCTIONS                           */
/*                                                                           */
/*****************************************************************************/



int msq_alloc_object (struct kddm_obj * obj_entry,
		      struct kddm_set * set,
		      objid_t objid)
{
	msq_object_t *msq_object;

	IPCDEBUG(DBG_KERIPC_MSG_LINKER, 3, "Alloc object (%ld;%ld)\n",
	      set->id, objid);

	msq_object = kmem_cache_alloc(msq_object_cachep, GFP_KERNEL);
	if (!msq_object)
		return -ENOMEM;

	msq_object->local_msq = NULL;
	obj_entry->object = msq_object;

	IPCDEBUG(DBG_KERIPC_MSG_LINKER, 3, "Alloc object (%ld;%ld): done %p\n",
	      set->id, objid, msq_object);

	return 0;
}



/** Handle a kddm set msq_queue id first touch
 *  @author Matthieu Fertré
 *
 *  @param  obj_entry  Kddm object descriptor.
 *  @param  set       Kddm set descriptor
 *  @param  objid     Id of the object to create.
 *
 *  @return  0 if everything is ok. Negative value otherwise.
 */
int msq_first_touch (struct kddm_obj * obj_entry,
		     struct kddm_set * set,
		     objid_t objid,
		     int flags)
{
	BUG(); // I should never get here !

	return 0;
}



/** Insert a new msg_queue id in local structures.
 *  @author Matthieu Fertré
 *
 *  @param  obj_entry  Descriptor of the object to insert.
 *  @param  set       Kddm set descriptor
 *  @param  objid     Id of the object to insert.
 */
int msq_insert_object (struct kddm_obj * obj_entry,
		       struct kddm_set * set,
		       objid_t objid)
{
	msq_object_t *msq_object;
	struct msg_queue *msq;

	IPCDEBUG(DBG_KERIPC_MSG_LINKER, 3, "Insert object (%ld;%ld)\n",
	      set->id, objid);

	msq_object = obj_entry->object;
	BUG_ON(!msq_object);

	/* Regular case, the kernel msg_queue struct is already allocated */
	if (msq_object->local_msq) {
		if (msq_object->mobile_msq.q_perm.id != -1)
			update_local_msq(msq_object->local_msq,
					 &msq_object->mobile_msq);

	} else {
		struct ipc_namespace *ns;

		ns = find_get_krg_ipcns();
		BUG_ON(!ns);

		/* This is the first time the object is inserted locally. We need
		 * to allocate kernel msq structures.
		 */
		msq = create_local_msq(ns, &msq_object->mobile_msq);
		msq_object->local_msq = msq;
		BUG_ON(IS_ERR(msq));

		put_ipc_ns(ns);
	}

	IPCDEBUG(DBG_KERIPC_MSG_LINKER, 3, "Insert object (%ld;%ld) : done %p\n",
	       set->id, objid, msq_object);

	return 0;
}



/** Invalidate a kddm object msqid.
 *  @author Matthieu Fertré
 *
 *  @param  obj_entry  Descriptor of the object to invalidate.
 *  @param  set       Kddm set descriptor
 *  @param  objid     Id of the object to invalidate
 */
int msq_invalidate_object (struct kddm_obj * obj_entry,
			   struct kddm_set * set,
			   objid_t objid)
{
	IPCDEBUG(DBG_KERIPC_MSG_LINKER, 3, "Invalidate object (%ld;%ld)\n",
	       set->id, objid);

	return KDDM_IO_KEEP_OBJECT;
}



/** Handle a msg queue remove.
 *  @author Matthieu Fertré
 *
 *  @param  obj_entry  Descriptor of the object to remove.
 *  @param  set       Kddm set descriptor.
 *  @param  padeid    Id of the object to remove.
 */
int msq_remove_object(void *object, struct kddm_set *set, objid_t objid)
{
	msq_object_t *msq_object;
	struct msg_queue *msq;
	struct ipc_namespace *ns;

	ns = find_get_krg_ipcns();
	BUG_ON(!ns);

	IPCDEBUG(DBG_KERIPC_MSG_LINKER, 3, "remove object (%ld;%ld)\n",
	       set->id, objid);

	msq_object = object;
	if (msq_object) {
		msq = msq_object->local_msq;
		local_msg_lock(ns, msq->q_perm.id);
		if (msq->is_master) {
			IPCDEBUG(DBG_KERIPC_MSG_LINKER, 4,
			       "Removing MASTER msg queue %d (%p)\n",
			       msq->q_perm.id, msq);
			local_master_freeque(ns, &msq->q_perm);
		} else {
			IPCDEBUG(DBG_KERIPC_MSG_LINKER, 4,
			       "Removing local msg queue %d (%p)\n",
			       msq->q_perm.id, msq);
			delete_local_msq(ns, msq);
		}

		kmem_cache_free (msq_object_cachep, msq_object);
	}

	IPCDEBUG(DBG_KERIPC_MSG_LINKER, 3, "remove object (%ld;%ld) : done\n",
	       set->id, objid);

	IPCDEBUG(DBG_KERIPC_MSG_LINKER, 3, "Import object %p : done\n",
	       msq_object);

	put_ipc_ns(ns);

	return 0;
}



/** Export an object
 *  @author Matthieu Fertré
 *
 *  @param  buffer    Buffer to export object data in.
 *  @param  object    The object to export data from.
 */
int msq_export_object (struct rpc_desc *desc,
		       struct kddm_set *set,
		       struct kddm_obj *obj_entry,
		       objid_t objid)
{
	msq_object_t *msq_object;
	int r;

	IPCDEBUG(DBG_KERIPC_MSG_LINKER, 3, "Import object %p\n",
	       obj_entry->object);

	msq_object = obj_entry->object;
	msq_object->mobile_msq = *msq_object->local_msq;

	r = rpc_pack(desc, 0, msq_object, sizeof(msq_object_t));

	IPCDEBUG(DBG_KERIPC_MSG_LINKER, 3, "Import object %p : done\n",
		 obj_entry->object);

	return r;
}



/** Import an object
 *  @author Matthieu Fertré
 *
 *  @param  object    The object to import data in.
 *  @param  buffer    Data to import in the object.
 */
int msq_import_object (struct rpc_desc *desc,
		       struct kddm_set *set,
		       struct kddm_obj *obj_entry,
		       objid_t objid)
{
	msq_object_t *msq_object, buffer;
	struct msg_queue *msq;
	int r;

	msq_object = obj_entry->object;

	IPCDEBUG(DBG_KERIPC_MSG_LINKER, 3, "Import object %p\n",
		 msq_object);

	r = rpc_unpack(desc, 0, &buffer, sizeof(msq_object_t));
	if (r)
		goto error;

	msq_object->mobile_msq = buffer.mobile_msq;

	if (msq_object->local_msq) {
		msq = msq_object->local_msq;
	}

error:
	IPCDEBUG(DBG_KERIPC_MSG_LINKER, 3, "Import object %p: %d\n",
		 msq_object, r);

	return r;
}



/****************************************************************************/

/* Init the msg queue id IO linker */

struct iolinker_struct msq_linker = {
	first_touch:       msq_first_touch,
	remove_object:     msq_remove_object,
	invalidate_object: msq_invalidate_object,
	insert_object:     msq_insert_object,
	linker_name:       "msg_queue",
	linker_id:         MSG_LINKER,
	alloc_object:      msq_alloc_object,
	export_object:     msq_export_object,
	import_object:     msq_import_object
};



/*****************************************************************************/
/*                                                                           */
/*                  MSG QUEUE KEY KDDM IO FUNCTIONS                          */
/*                                                                           */
/*****************************************************************************/

/* Init the msg queue key IO linker */

struct iolinker_struct msqkey_linker = {
	linker_name:       "msqkey",
	linker_id:         MSGKEY_LINKER,
};

/*****************************************************************************/
/*                                                                           */
/*                  MSG MASTER KDDM IO FUNCTIONS                             */
/*                                                                           */
/*****************************************************************************/

/* Init the msg master node IO linker */

struct iolinker_struct msqmaster_linker = {
	linker_name:       "msqmaster",
	linker_id:         MSGMASTER_LINKER,
};
