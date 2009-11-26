/** Basic coherence protocol actions.
 *  @file protocol_action.c
 *
 *  Copyright (C) 2001-2006, INRIA, Universite de Rennes 1, EDF.
 *  Copyright (C) 2006-2007, Renaud Lottiaux, Kerlabs.
 *
 *  The file implements the basic operations used by the KDDM coherence
 *  protocol.
 */

#include <linux/slab.h>
#include <linux/workqueue.h>
#include <linux/spinlock.h>
#include <kerrighed/sys/types.h>
#include <kerrighed/krgnodemask.h>
#include <kerrighed/krginit.h>

#include <kddm/kddm.h>
#include <kddm/object_server.h>
#include "protocol_action.h"
#include <net/krgrpc/rpcid.h>
#include <net/krgrpc/rpc.h>

int delayed_transfer_write_access (kerrighed_node_t dest_node, void *msg);

struct kmem_cache *kddm_da_cachep;



/*****************************************************************************/
/*                                                                           */
/*                              HELPER FUNCTIONS                             */
/*                                                                           */
/*****************************************************************************/



/** Wrapper to send a message to the object server handler.
 *  @author Renaud Lottiaux
 *
 *  @param  dest        Destination node.
 *  @param  type        Type of the message to send.
 *  @param  set_id      Id of the concerned set.
 *  @param  objid       Id of the concerned object.
 */
static inline void send_msg_to_object_server(kerrighed_node_t dest,
					     enum rpcid type,
					     struct kddm_ns *ns,
					     kddm_set_id_t set_id,
					     objid_t objid,
					     int flags,
					     kerrighed_node_t new_owner,
					     long req_id)
{
	msg_server_t msg_to_server;

	BUG_ON(dest < 0 || dest > KERRIGHED_MAX_NODES);

	msg_to_server.ns_id = ns->id;
	msg_to_server.set_id = set_id;
	msg_to_server.objid = objid;
	msg_to_server.flags = flags;
	msg_to_server.new_owner = new_owner;
	msg_to_server.reply_node = kerrighed_node_id;

	rpc_async(type, ns->rpc_comm, dest, &msg_to_server, sizeof(msg_server_t));
}



/** Wrapper to send a message to the object receiver handler.
 *  @author Renaud Lottiaux
 *
 *  @param  dest          Destination node.
 *  @param  set           Set hosting the object.
 *  @param  objid         Id of the concerned object.
 *  @param  obj_entry     Structure of the concerned object.
 *  @param  object_state  State of the concerned object.
 */
static inline int send_msg_to_object_receiver(kerrighed_node_t dest,
					      struct kddm_set *set,
					      objid_t objid,
					      struct kddm_obj *obj_entry,
					      kddm_obj_state_t object_state,
					      int flags,
					      long req_id)
{
	msg_object_receiver_t object_send_msg;
	struct rpc_desc *desc;
	int err = 0;

	BUG_ON(dest < 0 || dest > KERRIGHED_MAX_NODES);

	object_send_msg.ns_id = set->ns->id;
	object_send_msg.set_id = set->id;
	object_send_msg.objid = objid;
	object_send_msg.req_id = req_id;
	object_send_msg.object_state = object_state;
	object_send_msg.flags = flags;

	desc = rpc_begin(OBJECT_SEND, set->ns->rpc_comm, dest);
	if (!desc)
		OOM;

	err = rpc_pack_type(desc, object_send_msg);
	if (err)
		goto err_cancel;

	if (object_state & KDDM_OWNER_OBJ) {
		err = rpc_pack(desc, 0, &obj_entry->master_obj,
			       sizeof(masterObj_t));
		if (err)
			goto err_cancel;
	}

	if (!(flags & KDDM_NO_DATA)) {
		err = kddm_io_export_object(desc, set, obj_entry, objid, flags);
		if (err)
			goto err_cancel;
	}

	if (flags & KDDM_SYNC_OBJECT)
		rpc_unpack_type (desc, err);

	rpc_end(desc, 0);

	if (flags & KDDM_REMOVE_ON_ACK)
		destroy_kddm_obj_entry(set, obj_entry, objid, 0);

out:
	return err;

err_cancel:
	rpc_cancel(desc);
	goto out;
}



/** Request to synchronize the given object.
 *  @author Renaud Lottiaux
 *
 *  @param  set        Struct of the concerned set.
 *  @param  obj_entry  Structure of the concerned object.
 *  @param  objid      Id of the concerned object.
 */
int request_sync_object_and_unlock(struct kddm_set * set,
				   struct kddm_obj *obj_entry,
				   objid_t objid,
				   kddm_obj_state_t new_state)
{
	kerrighed_node_t dest;
	int err = 0, flags = KDDM_SYNC_OBJECT;

	dest = kddm_io_default_owner (set, objid);
	BUG_ON (dest == kerrighed_node_id);

	if ((OBJ_STATE(obj_entry) == READ_OWNER) &&
	    NODE_IN_SET(COPYSET(obj_entry), dest))
		flags |= KDDM_NO_DATA;

	kddm_change_obj_state (set, obj_entry, objid, new_state);

	put_kddm_obj_entry(set, obj_entry, objid);
	err = send_copy_on_read(set, obj_entry, objid, dest, flags);

	return err;
}



/*****************************************************************************/
/*                                                                           */
/*                         COHERENCE PROTOCOL ACTIONS                        */
/*                                                                           */
/*****************************************************************************/



/** Send object invalidation requests.
 *  @author Renaud Lottiaux
 *
 *  DO NOT invalidate the local copy and the sender copy.
 *
 *  @param set        Set the object to invalidate belong to.
 *  @param objid      Id of the object to invalidate.
 *  @param sender     The node which initiated the object invalidation
 *                    (i.e. the node who want a write copy of the object)
 */
void request_copies_invalidation(struct kddm_set * set,
				 struct kddm_obj *obj_entry,
				 objid_t objid,
				 kerrighed_node_t sender)
{
	msg_server_t msgToServer;
	krgnodemask_t nodes;

	BUG_ON(sender < 0 || sender > KERRIGHED_MAX_NODES);

	msgToServer.ns_id = set->ns->id;
	msgToServer.set_id = set->id;
	msgToServer.objid = objid;
	msgToServer.reply_node = sender;

	DUP2_SET(COPYSET(obj_entry), &nodes);
	krgnode_clear(kerrighed_node_id, nodes);
	krgnode_clear(sender, nodes);

	rpc_async_m(REQ_OBJECT_INVALID, set->ns->rpc_comm, &nodes,
		    &msgToServer, sizeof(msg_server_t));

	return;
}



/** Send object remove requests.
 *  @author Renaud Lottiaux
 *
 *  DO NOT invalidate the local copy and the sender copy.
 *
 *  @param set        Set the object to invalidate belong to.
 *  @param objid      Id of the object to invalidate.
 *  @param sender     The node which initiated the object invalidation
 *                    (i.e. the node who want a write copy of the object)
 */
int request_copies_remove(struct kddm_set * set,
			  struct kddm_obj *obj_entry,
			  objid_t objid,
			  kerrighed_node_t sender)
{
	int need_wait = 0;
	msg_server_t msgToServer;

	BUG_ON(sender < 0 || sender > KERRIGHED_MAX_NODES);

	REMOVE_FROM_SET(COPYSET(obj_entry), kerrighed_node_id);
	REMOVE_FROM_SET(RMSET(obj_entry), kerrighed_node_id);
	if (SET_IS_EMPTY(RMSET(obj_entry))) {
		BUG_ON (!SET_IS_EMPTY(COPYSET(obj_entry)));
		goto exit;
	}

	REMOVE_FROM_SET(COPYSET(obj_entry), sender);
	REMOVE_FROM_SET(RMSET(obj_entry), sender);

	if (!SET_IS_EMPTY(RMSET(obj_entry))) {
		msgToServer.ns_id = set->ns->id;
		msgToServer.set_id = set->id;
		msgToServer.objid = objid;
		msgToServer.reply_node = sender;

		rpc_async_m(REQ_OBJECT_REMOVE,
			    set->ns->rpc_comm, RMSET(obj_entry),
			    &msgToServer, sizeof(msg_server_t));

		need_wait = 1;
	}

	change_prob_owner (obj_entry, sender);

exit:
	return need_wait;
}



/** Send an object write request for the given object.
 *  @author Renaud Lottiaux
 *
 *  @param obj_entry   Object entry of the object.
 *  @param set         Set the object belong to.
 *  @param objid       Id of the object.
 *  @param flags       Sync / Async request, FT or not, etc...
 */
void request_object_on_write(struct kddm_set * set,
			     struct kddm_obj * obj_entry,
			     objid_t objid,
			     int flags)
{
	send_msg_to_object_server(get_prob_owner(obj_entry), REQ_OBJECT_COPY,
				  set->ns, set->id, objid,
				  flags | KDDM_OBJ_COPY_ON_WRITE,
				  kerrighed_node_id, 0);
}



/** Send an object read request for the given object.
 *  @author Renaud Lottiaux
 *
 *  @param obj_entry   Object entry of the object.
 *  @param set         Set the object belong to.
 *  @param objid       Id of the object.
 *  @param flags       Sync / Async request, FT or not, etc...
 */
void request_object_on_read(struct kddm_set * set,
			    struct kddm_obj * obj_entry,
			    objid_t objid,
			    int flags)
{
	send_msg_to_object_server(get_prob_owner(obj_entry), REQ_OBJECT_COPY,
				  set->ns, set->id, objid,
				  flags | KDDM_OBJ_COPY_ON_READ, 0, 0);
}



/** Send an object remove request for the given object the the object manager.
 *  @author Renaud Lottiaux
 *
 *  @param obj_entry   Object entry of the object.
 *  @param set         Set the object belong to.
 *  @param objid       Id of the object.
 */
void request_objects_remove_to_mgr(struct kddm_set * set,
				   struct kddm_obj * obj_entry,
				   objid_t objid)
{
	send_msg_to_object_server(get_prob_owner(obj_entry),
				  REQ_OBJECT_REMOVE_TO_MGR,
				  set->ns, set->id, objid, 0, 0, 0);
}



/** Send an object write copy to the given node.
 *  @author Renaud Lottiaux
 *
 *  @param dest_node  Node to send the write copy to.
 *  @param set        Set the object belong to.
 *  @param objid      Id of the object to send.
 *  @param obj_entry  Object entry of the object to send.
 */
void send_copy_on_write(struct kddm_set * set,
			struct kddm_obj * obj_entry,
			objid_t objid,
			kerrighed_node_t dest_node,
			int flags)
{
	kddm_obj_state_t state = WRITE_OWNER;

	BUG_ON (!is_locked_obj_entry(obj_entry));

	BUG_ON(dest_node < 0 || dest_node > KERRIGHED_MAX_NODES);
	BUG_ON(object_frozen_or_pinned(obj_entry));

	kddm_change_obj_state(set, obj_entry, objid, READ_OWNER);

	change_prob_owner(obj_entry, dest_node);

	send_msg_to_object_receiver(dest_node, set, objid, obj_entry, state,
				    flags, 0);
}

struct kddm_obj *send_copy_on_write_and_inv(struct kddm_set *set,
					    struct kddm_obj *obj_entry,
					    objid_t objid,
					    kerrighed_node_t dest,
					    int flags)
{
	/* TODO:we should probably release the obj lock in case the send sleep*/
	send_copy_on_write (set, obj_entry, objid, dest, 0);

	kddm_invalidate_local_object_and_unlock(obj_entry, set, objid,
						INV_COPY);

	return obj_entry;
}

/** Send an object read copy to the given node.
 *  @author Renaud Lottiaux
 *
 *  @param dest_node  Node to send the read copy to.
 *  @param set        Set the object belong to.
 *  @param objid      Id of the object to send.
 *  @param obj_entry  Object entry of the object to send.
 */
int send_copy_on_read(struct kddm_set * set,
		      struct kddm_obj * obj_entry,
		      objid_t objid,
		      kerrighed_node_t dest_node,
		      int flags)
{
	int r ;
	BUG_ON(dest_node < 0 || dest_node > KERRIGHED_MAX_NODES);

	r = send_msg_to_object_receiver(dest_node, set, objid,
					obj_entry, READ_COPY, flags, 0);

	ADD_TO_SET(COPYSET(obj_entry), dest_node);
	ADD_TO_SET(RMSET(obj_entry), dest_node);

	return r;
}



/** Send an "no object" answer.
 *  @author Renaud Lottiaux
 *
 *  @param dest_node  Node to send the message to.
 *  @param set        Set the object belong to.
 *  @param objid      Id of the object to send.
 *  @param obj_entry  Object entry of the object to send.
 */
void send_no_object(struct kddm_set * set,
		    struct kddm_obj * obj_entry,
		    objid_t objid,
		    kerrighed_node_t dest_node,
		    int send_ownership)
{
	int r = 0;
	BUG_ON(dest_node < 0 || dest_node > KERRIGHED_MAX_NODES);

	if (send_ownership) {
		r = change_prob_owner (obj_entry, dest_node);
		kddm_change_obj_state(set, obj_entry, objid, INV_COPY);
	}

	send_msg_to_object_server(dest_node, NO_OBJECT_SEND, set->ns,
				  set->id, objid, send_ownership,
				  kerrighed_node_id, 0);
}



/** Send object write access to the given node.
 *  @author Renaud Lottiaux
 *
 *  @param dest_node  Node to give object write access to.
 *  @param set        Set the object belong to.
 *  @param objid      Id of the object to send write access.
 *  @param obj_entry  Object entry of the object to send the write access.
 */
void transfer_write_access_and_unlock(struct kddm_set * set,
				      struct kddm_obj * obj_entry,
				      objid_t objid,
				      kerrighed_node_t dest_node,
				      masterObj_t * master_info)
{
	msg_injection_t msg;

	BUG_ON(dest_node < 0 || dest_node > KERRIGHED_MAX_NODES);

	msg.ns_id = set->ns->id;
	msg.set_id = set->id;
	msg.objid = objid;
	msg.req_id = 0;
	msg.owner_info = *master_info;

	if (object_frozen_or_pinned(obj_entry)) {
		queue_event(delayed_transfer_write_access, dest_node, set,
			    obj_entry, objid, &msg, sizeof(msg_injection_t));
		put_kddm_obj_entry(set, obj_entry, objid);

		return;
	}

	rpc_async(SEND_WRITE_ACCESS, set->ns->rpc_comm, dest_node,
		  &msg, sizeof(msg_injection_t));

	kddm_invalidate_local_object_and_unlock(obj_entry, set, objid,
						INV_COPY);
}



int delayed_transfer_write_access(kerrighed_node_t dest_node, void *_msg)
{
	msg_injection_t *msg = _msg;
	struct kddm_set *set;
	struct kddm_obj *obj_entry;

	BUG_ON(dest_node < 0 || dest_node > KERRIGHED_MAX_NODES);

	obj_entry = get_kddm_obj_entry(msg->ns_id, msg->set_id, msg->objid,
				       &set);
	if (obj_entry == NULL)
		return -EINVAL;

	transfer_write_access_and_unlock(set, obj_entry, msg->objid, dest_node,
					 &msg->owner_info);

	return 0;
}



void merge_ack_set(krgnodemask_t *obj_set,
		   krgnodemask_t *recv_set)
{
	krgnodemask_t v;

	__krgnodes_xor(&v, obj_set, recv_set, KERRIGHED_MAX_NODES);
	__krgnodes_and(obj_set, &v, recv_set, KERRIGHED_MAX_NODES);
}



/** Send an object invalidation ack to the given node.
 *  @author Renaud Lottiaux
 *
 *  @param dest_node  Node to send the invalidation ack to.
 *  @param set        Set the object belongs to.
 *  @param objid      Id of the object.
 */
void send_invalidation_ack(struct kddm_set * set,
			   objid_t objid,
			   kerrighed_node_t dest_node)
{
	BUG_ON(dest_node < 0 || dest_node > KERRIGHED_MAX_NODES);

	send_msg_to_object_server(dest_node, INVALIDATION_ACK, set->ns,
				  set->id, objid, 0, kerrighed_node_id,
				  0);
}



/** Send an object remove ack to the given node.
 *  @author Renaud Lottiaux
 *
 *  @param dest_node  Node to send the remove ack to.
 *  @param set        Set the object belongs to.
 *  @param objid      Id of the object.
 */
void send_remove_ack(struct kddm_set * set,
		     objid_t objid,
		     kerrighed_node_t dest_node,
		     int flags)
{
	BUG_ON(dest_node < 0 || dest_node > KERRIGHED_MAX_NODES);

	send_msg_to_object_server(dest_node, REMOVE_ACK, set->ns, set->id,
				  objid, flags, 0, 0);
}



/** Send an object remove ack2 to the given node.
 *  @author Renaud Lottiaux
 *
 *  @param dest_node  Node to send the remove ack to.
 *  @param set        Set the object belongs to.
 *  @param objid      Id of the object.
 */
void send_remove_ack2(struct kddm_set * set,
		      objid_t objid,
		      kerrighed_node_t dest_node)
{
	msg_server_t msg_to_server;

	BUG_ON(dest_node < 0 || dest_node > KERRIGHED_MAX_NODES);

	msg_to_server.ns_id = set->ns->id;
	msg_to_server.set_id = set->id;
	msg_to_server.objid = objid;
	msg_to_server.req_id = 0;

	rpc_async(REMOVE_ACK2, set->ns->rpc_comm, dest_node,
		  &msg_to_server, sizeof(msg_server_t));
}



/** Send a global objects remove ack from the manager node to the given node.
 *  @author Renaud Lottiaux
 *
 *  @param dest_node  Node to send the removes ack to.
 *  @param set        Set the object belongs to.
 *  @param objid      Id of the object.
 */
void send_remove_object_done(struct kddm_set * set,
			     objid_t objid,
			     kerrighed_node_t dest_node,
			     krgnodemask_t *rmset)
{
	rm_done_msg_server_t msg;

	BUG_ON(dest_node < 0 || dest_node > KERRIGHED_MAX_NODES);

	msg.ns_id = set->ns->id;
	msg.set_id = set->id;
	msg.objid = objid;
	msg.req_id = 0;

	DUP2_SET(rmset, &msg.rmset);

	rpc_async(REMOVE_DONE, set->ns->rpc_comm, dest_node,
		  &msg, sizeof(rm_done_msg_server_t));
}



/*****************************************************************************/
/*                                                                           */
/*                         OBJECT FIRST TOUCH ACTIONS                        */
/*                                                                           */
/*****************************************************************************/



/** Do an object first touch.
 *  @author Renaud Lottiaux
 *
 *  @param set       Set the object belong to.
 *  @param objid     Id of the object to first touch.
 */
int object_first_touch_no_wakeup(struct kddm_set * set,
				 struct kddm_obj * obj_entry,
				 objid_t objid,
				 kddm_obj_state_t object_state,
				 int flags)
{
	int res;

	kddm_change_obj_state (set, obj_entry, objid, INV_FILLING);

	/* TODO: we should probably release the obj_lock during the FT */
	res = kddm_io_first_touch_object(obj_entry, set, objid, flags);

	if (res)
		return res;

	if (object_state != INV_FILLING) {
		kddm_change_obj_state(set, obj_entry, objid, object_state);

		if (object_state & KDDM_OWNER_OBJ) {
			CLEAR_SET(COPYSET(obj_entry));
			ADD_TO_SET(COPYSET(obj_entry), kerrighed_node_id);
			ADD_TO_SET(RMSET(obj_entry), kerrighed_node_id);
		}
	}

	return res;
}



/** Do an object first touch.
 *  @author Renaud Lottiaux
 *
 *  @param set       Set the object belong to.
 *  @param objid     Id of the object to first touch.
 */
int object_first_touch(struct kddm_set * set,
		       struct kddm_obj * obj_entry,
		       objid_t objid,
		       kddm_obj_state_t object_state,
		       int flags)
{
	int res;

	BUG_ON(kddm_ft_linked(set) && !I_AM_DEFAULT_OWNER(set, objid));

	res = object_first_touch_no_wakeup(set, obj_entry, objid, INV_FILLING,
					   flags);
	if (res < 0)
		return res;

	kddm_insert_object (set, objid, obj_entry, object_state);

	return res;
}



/** Send back an object first touch request to the faulting node.
 *  @author Renaud Lottiaux
 *
 *  @param dest_node  Node to send the request to.
 *  @param set        Set the object belong to.
 *  @param objid      Id of the object to send a first touch request for.
 *  @param req_type   Type of the first touch request (read or write).
 *  @param obj_entry  Object entry of the object.
 */
void send_back_object_first_touch(struct kddm_set * set,
				  struct kddm_obj * obj_entry,
				  objid_t objid,
				  kerrighed_node_t dest_node,
				  int flags,
				  int req_type)
{
	msg_server_t msgToServer;

	BUG_ON(dest_node < 0 || dest_node > KERRIGHED_MAX_NODES);

	msgToServer.ns_id = set->ns->id;
	msgToServer.set_id = set->id;
	msgToServer.objid = objid;
	msgToServer.req_id = 0;
	msgToServer.reply_node = kerrighed_node_id;
	msgToServer.flags = flags;

	rpc_async(req_type, set->ns->rpc_comm, dest_node,
		  &msgToServer, sizeof(msg_server_t));

	change_prob_owner(obj_entry, dest_node);
	kddm_change_obj_state(set, obj_entry, objid, INV_COPY);
}


/** Change the probable owner on a given node.
 *  @author Renaud Lottiaux
 *
 *  @param set        Set the object belong to.
 *  @param objid      Id of the object to change the owner
 *  @param dest_node  Node to send the request to.
 *  @param new_owner  The new default owner.
 */
void request_change_prob_owner(struct kddm_set * set,
			       struct kddm_obj * obj_entry,
			       objid_t objid,
			       kerrighed_node_t dest_node,
			       kerrighed_node_t new_owner)
{
	msg_server_t msg_to_server;

	/* This function can only be called in reconfiguration phase */
	BUG_ON (!kddm_frozen(set));
	BUG_ON(!is_locked_obj_entry(obj_entry));

	msg_to_server.ns_id = set->ns->id;
	msg_to_server.set_id = set->id;
	msg_to_server.objid = objid;
	msg_to_server.new_owner = new_owner;

#ifdef CONFIG_DEBUG_SPINLOCK
	lockdep_off();
#endif
	unlock_obj_entry(obj_entry);
#ifdef CONFIG_DEBUG_SPINLOCK
	lockdep_on();
#endif
	rpc_sync(KDDM_CHANGE_PROB_OWNER, set->ns->rpc_comm, dest_node,
		 &msg_to_server, sizeof(msg_server_t));

#ifdef CONFIG_DEBUG_SPINLOCK
	lockdep_off();
#endif
	lock_obj_entry(obj_entry);
#ifdef CONFIG_DEBUG_SPINLOCK
	lockdep_on();
#endif
}


/*****************************************************************************/
/*                                                                           */
/*                          OBJECT INJECTION ACTIONS                         */
/*                                                                           */
/*****************************************************************************/



void send_change_ownership_req(struct kddm_set * set,
			       struct kddm_obj * obj_entry,
			       objid_t objid,
			       kerrighed_node_t dest_node,
			       masterObj_t * master_info)
{
	msg_injection_t changeOwnerMsg;

	BUG_ON(dest_node < 0 || dest_node > KERRIGHED_MAX_NODES);

	changeOwnerMsg.ns_id = set->ns->id;
	changeOwnerMsg.set_id = set->id;
	changeOwnerMsg.objid = objid;
	changeOwnerMsg.reply_node = kerrighed_node_id;
	changeOwnerMsg.owner_info = *master_info;

	rpc_async(SEND_OWNERSHIP, set->ns->rpc_comm, dest_node,
		  &changeOwnerMsg, sizeof(msg_injection_t));

	kddm_change_obj_state(set, obj_entry, objid, WAIT_CHG_OWN_ACK);
}



void ack_change_object_owner(struct kddm_set * set,
			     struct kddm_obj * obj_entry,
			     objid_t objid,
			     kerrighed_node_t dest_node,
			     masterObj_t * master_info)
{
	msg_server_t msgToServer;

	BUG_ON(dest_node < 0 || dest_node > KERRIGHED_MAX_NODES);

	msgToServer.ns_id = set->ns->id;
	msgToServer.set_id = set->id;
	msgToServer.objid = objid;
	msgToServer.reply_node = kerrighed_node_id;
	msgToServer.new_owner = kerrighed_node_id;

	obj_entry->master_obj = *master_info;
	kddm_change_obj_state(set, obj_entry, objid, READ_OWNER);

	rpc_async(CHANGE_OWNERSHIP_ACK, set->ns->rpc_comm, dest_node,
		  &msgToServer, sizeof (msg_server_t));
}


kerrighed_node_t choose_injection_node_in_copyset(struct kddm_obj * object)
{
	int i = 0, res = -1;

	while (i < KERRIGHED_MAX_NODES && res == -1) {
		if (krgnode_online(i)
		    && i != kerrighed_node_id
		    && NODE_IN_SET(COPYSET(object), i)) {
			res = i;
			break;
		}
		i++;
	}
	return res;
}



/*****************************************************************************/
/*                                                                           */
/*                       EVENT QUEUE ACTIONS AND MANAGEMENT                  */
/*                                                                           */
/*****************************************************************************/



typedef struct kddm_delayed_action {
	struct list_head list;
	struct delayed_work work;
	queue_event_handler_t fn;
	kerrighed_node_t sender;
	struct kddm_set *set;
	objid_t objid;
	void *data;
} kddm_delayed_action_t;

static struct workqueue_struct *kddm_wq;

void kddm_workqueue_handler(struct work_struct *work)
{
	struct kddm_delayed_action *action;

	action = container_of(work, struct kddm_delayed_action, work.work);

	spin_lock(&action->set->event_lock);
	list_del(&action->list);
	spin_unlock(&action->set->event_lock);

	action->fn(action->sender, action->data);
	kfree(action->data);
	kmem_cache_free(kddm_da_cachep, action);

	cond_resched();
}

void flush_kddm_event(struct kddm_set *set,
		      objid_t objid)
{
	struct kddm_delayed_action *action;

	spin_lock(&set->event_lock);
	list_for_each_entry(action, &set->event_list, list) {
		if (action->objid == objid) {
			if (cancel_delayed_work (&action->work))
				queue_delayed_work(kddm_wq, &action->work, 0);
		}
	}
	spin_unlock(&set->event_lock);
}

void freeze_kddm_event(struct kddm_set *set)
{
	struct kddm_delayed_action *action;

	spin_lock(&set->event_lock);
	list_for_each_entry(action, &set->event_list, list)
		cancel_delayed_work (&action->work);
	spin_unlock(&set->event_lock);
}

void unfreeze_kddm_event(struct kddm_set *set)
{
	struct kddm_delayed_action *action;
	int delay = 1;

	spin_lock(&set->event_lock);
	list_for_each_entry(action, &set->event_list, list)
		queue_delayed_work(kddm_wq, &action->work, delay);
	spin_unlock(&set->event_lock);
}

void queue_event(queue_event_handler_t fn,
		 kerrighed_node_t sender,
		 struct kddm_set *set,
		 struct kddm_obj * obj_entry,
		 objid_t objid,
		 void *dataIn,
		 size_t data_size)
{
	struct kddm_delayed_action *action;
	int delay = 1;
	void *data;

	action = kmem_cache_alloc(kddm_da_cachep, GFP_ATOMIC);
	data = kmalloc(data_size, GFP_ATOMIC);
	memcpy(data, dataIn, data_size);
	action->fn = fn;
	action->sender = sender;
	action->set = set;
	action->objid = objid;
	action->data = data;

	INIT_DELAYED_WORK(&action->work, kddm_workqueue_handler);

	spin_lock(&set->event_lock);
	list_add_tail(&action->list, &set->event_list);
	spin_unlock(&set->event_lock);

	SET_OBJECT_PENDING(obj_entry);

	queue_delayed_work(kddm_wq, &action->work, delay);
}



void start_run_queue_thread()
{
	kddm_da_cachep = KMEM_CACHE(kddm_delayed_action, SLAB_PANIC);

	kddm_wq = create_singlethread_workqueue("kddm");
}



void stop_run_queue_thread()
{
	destroy_workqueue (kddm_wq);
}
