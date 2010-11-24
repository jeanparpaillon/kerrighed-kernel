/** Object Server.
 *  @file object_server.c
 *
 *  Copyright (C) 2001-2006, INRIA, Universite de Rennes 1, EDF.
 *  Copyright (C) 2006-2007, Renaud Lottiaux, Kerlabs.
 */

#include <linux/kernel.h>
#include <kerrighed/sys/types.h>
#include <kerrighed/krginit.h>

#include <net/krgrpc/rpcid.h>
#include <net/krgrpc/rpc.h>
#include <kddm/kddm.h>
#include <kddm/object_server.h>
#include "protocol_action.h"

struct rpc_synchro *object_server;
struct rpc_synchro *object_server_may_block;

static inline struct kddm_obj *get_alloc_kddm_obj_entry_lock_free (int ns_id,
                                                   kddm_set_id_t set_id,
                                                   objid_t objid,
                                                   struct kddm_set **kddm_set)
{
	struct kddm_obj *obj = NULL;

	*kddm_set = find_get_kddm_set_lock_free(ns_id, set_id);

	if (*kddm_set) {
		BUG_ON(!kddm_frozen(*kddm_set));
		obj = ___get_alloc_kddm_obj_entry (*kddm_set, objid,
						   KDDM_LOCK_FREE);
		put_kddm_set(*kddm_set);
	}
	return obj;
}

/** Forward a message to the supposed correct prob Owner.
 *  @author Renaud Lottiaux
 */
static inline void forward_object_server_msg (struct kddm_obj * obj_entry,
					      struct kddm_set *set,
					      enum rpcid msg_type,
					      void *_msg)
{
	msg_server_t *msg = (msg_server_t *)_msg;
	kerrighed_node_t prob_owner;

	if (obj_entry == NULL)
		prob_owner = kddm_io_default_owner(set, msg->objid);
	else
		prob_owner = get_prob_owner(obj_entry);

	BUG_ON(prob_owner == kerrighed_node_id);

	msg->req_id = 0;
	rpc_async(msg_type, set->ns->rpc_comm, prob_owner,
		  _msg, sizeof(msg_server_t));
}



/*****************************************************************************/
/*                                                                           */
/*                              REQUEST HANDLERS                             */
/*                                                                           */
/*****************************************************************************/



/** Handle an invalidation ack receive.
 *  @author Renaud Lottiaux
 *
 *  @param msg  Message received from the requesting node.
 */
static inline int __handle_invalidation_ack (kerrighed_node_t sender,
					     void *_msg)
{
	msg_server_t *msg = _msg;
	struct kddm_obj *obj_entry;
	struct kddm_set *set;
	kerrighed_node_t dest;

	BUG_ON (sender < 0 || sender > KERRIGHED_MAX_NODES);

	obj_entry = get_kddm_obj_entry (msg->ns_id, msg->set_id, msg->objid,
					&set);

	/* Managing this message on a frozen object could lead to some bad
	 * behaviors. For instance, sending a write copy since we actually
	 * cannot do it because of the frozen state.
	 */
	if (object_frozen_or_pinned (obj_entry)) {
		queue_event (__handle_invalidation_ack, sender, set, obj_entry,
			     msg->objid, msg, sizeof (msg_server_t));

		goto exit;
	}

	switch (OBJ_STATE(obj_entry)) {
	  case INV_FILLING:
		  if (get_prob_owner(obj_entry) == kerrighed_node_id)
			  goto handle_ack;
		  /* else fall through */
	  case INV_COPY:
	  case READ_COPY:
	  case WAIT_OBJ_READ:
		  forward_object_server_msg (obj_entry, set, INVALIDATION_ACK,
					     msg);
		  break;

	  case WAIT_OBJ_WRITE:
		  ADD_TO_SET (COPYSET(obj_entry), msg->reply_node);
		  break;

	  case READ_OWNER:
		  REMOVE_FROM_SET (COPYSET(obj_entry), msg->reply_node);

		  /* If the local object is the last one in the cluster
		     and it is not used locally, we just remote it ! */
		  break;

	  case WAIT_CHG_OWN_ACK:
		  REMOVE_FROM_SET (COPYSET(obj_entry), msg->reply_node);

		  BUG_ON(SET_IS_EMPTY (COPYSET(obj_entry)));

		  if (OBJ_EXCLUSIVE (obj_entry)) {
			  CLEAR_OBJECT_RM_SO_ACK(obj_entry);
			  dest = sender;

			  BUG_ON (dest == 1);

			  obj_entry = send_copy_on_write_and_inv (
				  set, obj_entry, msg->objid, dest,
				  KDDM_IO_FLUSH);

			  /* Wake up the set_flush function */

			  wake_up_on_wait_object (obj_entry, set);

			  goto exit_no_unlock;
		  }
		  else {
			  dest = choose_injection_node_in_copyset (obj_entry);

			  BUG_ON (dest == 1);

			  send_change_ownership_req (set, obj_entry,
						     msg->objid, dest,
						     &obj_entry->master_obj);
		  }
		  break;

	  case WAIT_ACK_INV:
handle_ack:
		  if (!NODE_IN_SET (COPYSET(obj_entry), sender))
			  printk ("Problem with object (%ld;%ld)\n",
				  set->id, msg->objid);
		  BUG_ON(!NODE_IN_SET (COPYSET(obj_entry), sender));
		  REMOVE_FROM_SET (COPYSET(obj_entry), sender);
		  BUG_ON(SET_IS_EMPTY (COPYSET(obj_entry)));

		  if (OBJ_EXCLUSIVE (obj_entry) &&
		      (OBJ_STATE(obj_entry) != INV_FILLING)) {
			  kddm_insert_object (set, msg->objid, obj_entry,
					      WRITE_OWNER);
		  }

		  break;

	  case WAIT_ACK_WRITE:
		  BUG_ON(!NODE_IN_SET (COPYSET(obj_entry), sender));
		  REMOVE_FROM_SET (COPYSET(obj_entry), sender);
		  BUG_ON(SET_IS_EMPTY (COPYSET(obj_entry)));

		  if (OBJ_EXCLUSIVE (obj_entry)) {
			  kddm_change_obj_state (set, obj_entry, msg->objid,
						 WRITE_OWNER);
			  wake_up_on_wait_object (obj_entry, set);
		  }
		  break;

	  case WAIT_OBJ_RM_ACK:
		  /* Local remove is in competition with a remote flush.
		   * Just ignore this message and continue to wait for the
		   * remove ACK.
		   */
		  break;

	  default:
		  STATE_MACHINE_ERROR (msg->set_id, msg->objid, obj_entry);
		  break;
	}

exit:
	put_kddm_obj_entry(set, obj_entry, msg->objid);

exit_no_unlock:
	return 0;
}

void handle_invalidation_ack (struct rpc_desc* desc,
			     void *_msg, size_t size){
	__handle_invalidation_ack(desc->client, _msg);
}



/** Handle a remove ack receive.
 *  @author Renaud Lottiaux
 *
 *  @param msg  Message received from the requesting node.
 */
void handle_remove_ack (struct rpc_desc* desc,
		       void *_msg, size_t size)
{
	msg_server_t *msg = _msg;
	struct kddm_obj *obj_entry;
	struct kddm_set *set;

	BUG_ON (desc->client < 0 || desc->client > KERRIGHED_MAX_NODES);

	obj_entry = get_kddm_obj_entry (msg->ns_id, msg->set_id, msg->objid,
					&set);

	switch (OBJ_STATE(obj_entry)) {
	  case WAIT_OBJ_RM_DONE:
		  ADD_TO_SET (RMSET(obj_entry), desc->client);
		  break;

	  case WAIT_OBJ_RM_ACK:
		  BUG_ON(!NODE_IN_SET (RMSET(obj_entry), desc->client));

		  REMOVE_FROM_SET (COPYSET(obj_entry), desc->client);
		  REMOVE_FROM_SET (RMSET(obj_entry), desc->client);

		  if (msg->flags & KDDM_NEED_OBJ_RM_ACK2)
			  SET_OBJECT_RM_ACK2(obj_entry);

		  if (SET_IS_EMPTY (RMSET(obj_entry))) {
			  BUG_ON (!SET_IS_EMPTY (COPYSET(obj_entry)));
			  if (TEST_OBJECT_RM_ACK2(obj_entry)) {
				  send_remove_ack2 (set, msg->objid,
						    kddm_io_default_owner(set,
									  msg->objid));
				  CLEAR_OBJECT_RM_ACK2(obj_entry);
			  }
			  wake_up_on_wait_object (obj_entry, set);
		  }
		  break;

	  default:
		  STATE_MACHINE_ERROR (msg->set_id, msg->objid, obj_entry);
		  break;
	}

	put_kddm_obj_entry(set, obj_entry, msg->objid);

	return;
}


/** Handle a remove ack .
 *  @author Renaud Lottiaux
 *
 *  @param msg  Message received from the requesting node.
 */
void handle_remove_ack2 (struct rpc_desc* desc,
		       void *_msg, size_t size)
{
	msg_server_t *msg = _msg;
	struct kddm_obj *obj_entry;
	struct kddm_set *set;

	BUG_ON (desc->client < 0 || desc->client > KERRIGHED_MAX_NODES);

	obj_entry = get_kddm_obj_entry (msg->ns_id, msg->set_id, msg->objid,
					&set);

	switch (OBJ_STATE(obj_entry)) {
	  case WAIT_OBJ_WRITE:
	  case WAIT_OBJ_READ:
		  kddm_change_obj_state (set, obj_entry, msg->objid,
					 INV_OWNER);
		  wake_up_on_wait_object (obj_entry, set);

		  /* Fall through */
	  case INV_OWNER:
		  break;

	  case WAIT_OBJ_RM_ACK2:
		  destroy_kddm_obj_entry(set, obj_entry, msg->objid, 1);
		  goto exit_no_unlock;

	  default:
		  STATE_MACHINE_ERROR (msg->set_id, msg->objid, obj_entry);
		  break;
	}

	put_kddm_obj_entry(set, obj_entry, msg->objid);
exit_no_unlock:
	return;
}



/** Handle a global remove ack receive.
 *  @author Renaud Lottiaux
 *
 *  @param msg  Message received from the requesting node.
 */
void handle_remove_done (struct rpc_desc* desc,
			void *_msg, size_t size)
{
	rm_done_msg_server_t *msg = _msg;
	struct kddm_obj *obj_entry;
	struct kddm_set *set;

	BUG_ON (desc->client < 0 || desc->client > KERRIGHED_MAX_NODES);

	obj_entry = get_kddm_obj_entry (msg->ns_id, msg->set_id, msg->objid,
					&set);

	switch (OBJ_STATE(obj_entry)) {
	  case WAIT_OBJ_RM_DONE:
		  merge_ack_set(RMSET(obj_entry), &msg->rmset);
		  if (SET_IS_EMPTY(RMSET(obj_entry)))
			  wake_up_on_wait_object (obj_entry, set);
		  else
			  kddm_change_obj_state(set, obj_entry, msg->objid,
						WAIT_OBJ_RM_ACK);
		  break;

	  default:
		  STATE_MACHINE_ERROR (msg->set_id, msg->objid, obj_entry);
		  break;
	}

	put_kddm_obj_entry(set, obj_entry, msg->objid);

	return;
}



/** Handle an object invalidation request.
 *  @author Renaud Lottiaux
 *
 *  @param msg  Message received from the requesting node.
 */
static inline
int __handle_object_invalidation (kerrighed_node_t sender,
				  void *_msg)
{
	msg_server_t *msg = _msg;
	struct kddm_obj *obj_entry;
	struct kddm_set *set;

	BUG_ON (sender < 0 || sender > KERRIGHED_MAX_NODES);

	obj_entry = get_kddm_obj_entry (msg->ns_id, msg->set_id, msg->objid,
					&set);

	if (object_frozen_or_pinned (obj_entry)) {
		queue_event (__handle_object_invalidation, sender, set,
			     obj_entry, msg->objid, msg,
			     sizeof (msg_server_t));

		goto exit;
	}

	switch (OBJ_STATE(obj_entry)) {
	  case INV_COPY:
		  /* Nothing to do... */
		  break;

	  case READ_COPY:
		  kddm_invalidate_local_object_and_unlock (obj_entry, set,
							   msg->objid,
							   INV_COPY);

		  change_prob_owner (obj_entry, msg->reply_node);
		  send_invalidation_ack (set, msg->objid, msg->reply_node);
		  goto exit_no_unlock;

	  case WAIT_OBJ_READ:
	  case INV_FILLING:
		  queue_event (__handle_object_invalidation, sender, set,
			       obj_entry, msg->objid, msg,
			       sizeof (msg_server_t));
		  break;

	  case WAIT_OBJ_WRITE:
		  kddm_invalidate_local_object_and_unlock (obj_entry, set,
							   msg->objid,
							   WAIT_OBJ_WRITE);

		  change_prob_owner (obj_entry, msg->reply_node);
		  send_invalidation_ack (set, msg->objid, msg->reply_node);
		  goto exit_no_unlock;

	  default:
		  STATE_MACHINE_ERROR (msg->set_id, msg->objid, obj_entry);
		  break;
	}

exit:
	put_kddm_obj_entry(set, obj_entry, msg->objid);
exit_no_unlock:

	return 0;
}

void handle_object_invalidation (struct rpc_desc* desc,
                                void *_msg, size_t size)
{
	__handle_object_invalidation(desc->client, _msg);
};



/** Handle an object remove request.
 *  @author Renaud Lottiaux
 *
 *  @param msg  Message received from the requesting node.
 */
static inline int __handle_object_remove_req (kerrighed_node_t sender,
					      void *_msg)
{
	msg_server_t *msg = _msg;
	struct kddm_obj *obj_entry;
	struct kddm_set *set;
	int flag = 0;

	BUG_ON (sender < 0 || sender > KERRIGHED_MAX_NODES);

	obj_entry = get_kddm_obj_entry (msg->ns_id, msg->set_id, msg->objid,
					&set);

	if (obj_entry == NULL) {
		send_remove_ack (set, msg->objid, msg->reply_node, 0);
		goto exit_no_unlock;
	}

	if (object_frozen_or_pinned (obj_entry)) {

		queue_event (__handle_object_remove_req, sender, set,
			     obj_entry, msg->objid, msg,
			     sizeof (msg_server_t));

		goto exit;
	}

	if (kddm_io_default_owner(set, msg->objid) == kerrighed_node_id)
		flag = KDDM_NEED_OBJ_RM_ACK2;

	switch (OBJ_STATE(obj_entry)) {
	  case INV_COPY:
	  case READ_COPY:
		  if (flag) {
			  kddm_change_obj_state (set, obj_entry, msg->objid,
						 WAIT_OBJ_RM_ACK2);

			  kddm_io_remove_object_and_unlock(obj_entry, set,
							   msg->objid, NULL);

			  send_remove_ack (set, msg->objid, msg->reply_node,
					   flag);

			  goto exit_no_unlock;
		  }
		  destroy_kddm_obj_entry(set, obj_entry, msg->objid, 1);

		  send_remove_ack (set, msg->objid, msg->reply_node, flag);
		  goto exit_no_unlock;

	  case WAIT_OBJ_WRITE:
	  case WAIT_OBJ_READ:
		  BUG_ON(TEST_OBJECT_PINNED(obj_entry));

		  kddm_io_remove_object_and_unlock (obj_entry, set,
						    msg->objid, NULL);

		  send_remove_ack (set, msg->objid, msg->reply_node, flag);
		  goto exit_no_unlock;

	  case INV_FILLING:
		  queue_event (__handle_object_remove_req, sender, set,
			       obj_entry, msg->objid, msg,
			       sizeof (msg_server_t));
		  break;

	  default:
		  STATE_MACHINE_ERROR (msg->set_id, msg->objid, obj_entry);
		  break;
	}

exit:
	put_kddm_obj_entry(set, obj_entry, msg->objid);
exit_no_unlock:

	return 0;
}

void handle_object_remove_req (struct rpc_desc* desc,
			      void *_msg, size_t size)
{
	__handle_object_remove_req(desc->client, _msg);
};



/** Handle an object ownership modification request.
 *  @author Renaud Lottiaux
 *
 *  @param sender  Node sending the ownership.
 *  @param msg     Message received from the requesting node.
 */
static inline int __handle_send_ownership_req (kerrighed_node_t sender,
					       void *_msg)
{
	msg_injection_t *msg = _msg;
	struct kddm_obj *obj_entry;
	struct kddm_set *set;

	BUG_ON (sender < 0 || sender > KERRIGHED_MAX_NODES);

	obj_entry = get_kddm_obj_entry (msg->ns_id, msg->set_id, msg->objid,
					&set);

	switch (OBJ_STATE(obj_entry)) {
	  case INV_COPY:
		  /* Nothing to do */
		  break;

	  case READ_COPY:
		  ack_change_object_owner (set, obj_entry, msg->objid,
					   msg->reply_node, &msg->owner_info);
		  break;

	  case WAIT_OBJ_WRITE:
		  send_invalidation_ack (set, msg->objid, msg->reply_node);
		  break;

	  case INV_FILLING:
		  queue_event (__handle_send_ownership_req, sender, set,
			       obj_entry, msg->objid, msg,
			       sizeof (msg_injection_t));
		  break;


	  default:
		  STATE_MACHINE_ERROR (msg->set_id, msg->objid, obj_entry);
		  break;
	}

	put_kddm_obj_entry(set, obj_entry, msg->objid);

	return 0;
}

void handle_send_ownership_req (struct rpc_desc* desc,
                               void *_msg, size_t size){
	__handle_send_ownership_req(desc->client, _msg);
};


/** Handle an object ownership modification request.
 *  @author Renaud Lottiaux
 *
 *  @param sender  Node sending the ownership.
 *  @param msg     Message received from the requesting node.
 */
void handle_change_ownership_ack (struct rpc_desc* desc,
                                 void *_msg, size_t size)
{
	msg_server_t *msg = _msg;
	struct kddm_obj *obj_entry;
	struct kddm_set *set;

	BUG_ON (desc->client < 0 || desc->client > KERRIGHED_MAX_NODES);

	obj_entry = get_kddm_obj_entry (msg->ns_id, msg->set_id, msg->objid,
					&set);

	if (OBJ_STATE(obj_entry) == WAIT_CHG_OWN_ACK)
	{
		change_prob_owner(obj_entry, msg->new_owner);

		if (TEST_OBJECT_RM_SO_ACK(obj_entry)) {
			CLEAR_OBJECT_RM_SO_ACK(obj_entry);
			destroy_kddm_obj_entry(set, obj_entry, msg->objid, 0);
			return;
		}
		else
			/* Wake up the set_flush_object function */
			wake_up_on_wait_object (obj_entry, set);
	}
	else
		STATE_MACHINE_ERROR (msg->set_id, msg->objid, obj_entry);

	put_kddm_obj_entry(set, obj_entry, msg->objid);

	return ;
}



/** Handle an object receive.
 *  @author Renaud Lottiaux
 *
 *  @param sender  Node sending the object.
 *  @param msg     Message received from the requesting node.
 */
void handle_object_receive (struct rpc_desc* desc,
                           void *_msg, size_t size)
{
	msg_object_receiver_t *msg = _msg;
	kddm_obj_state_t obj_state = 0;
	struct kddm_obj *obj_entry;
	struct kddm_set *set;
	masterObj_t master_info;
	int res, dont_insert = 0 ;

	BUG_ON (desc->client < 0 || desc->client > KERRIGHED_MAX_NODES);

	if (msg->object_state & KDDM_OWNER_OBJ) {
		res = rpc_unpack(desc, 0, &master_info, sizeof(masterObj_t));
		if (res)
			return;
	}

	obj_entry = get_alloc_kddm_obj_entry (msg->ns_id, msg->set_id,
					      msg->objid, &set);

	if (!obj_entry) {
		if (msg->flags & KDDM_SYNC_OBJECT) {
			res = -EINVAL;
			rpc_pack_type(desc, res);
		}
		return;
	}

	if (msg->object_state & KDDM_OWNER_OBJ) {
		DUP2_SET(&master_info.rmset, &obj_entry->master_obj.rmset);
		ADD_TO_SET(RMSET(obj_entry), desc->client);
		ADD_TO_SET(RMSET(obj_entry), kerrighed_node_id);
	}

	switch (OBJ_STATE(obj_entry)) {
	  case INV_COPY:
		  if (msg->flags & KDDM_SYNC_OBJECT)
			  obj_state = READ_COPY;
		  else {
			  change_prob_owner(obj_entry, kerrighed_node_id);
			  obj_state = WRITE_GHOST;
		  }
		  break;

	  case WAIT_OBJ_WRITE:
		  change_prob_owner(obj_entry, kerrighed_node_id);
		  ADD_TO_SET(COPYSET(obj_entry), desc->client);
		  merge_ack_set(COPYSET(obj_entry), &master_info.copyset);
		  ADD_TO_SET(COPYSET(obj_entry), kerrighed_node_id);
		  if (OBJ_EXCLUSIVE2 (COPYSET(obj_entry)))
			  obj_state = msg->object_state;
		  else
			  obj_state = WAIT_ACK_INV;

		  break;

	  case WAIT_OBJ_READ:
		  change_prob_owner(obj_entry, desc->client);
		  obj_state = msg->object_state;
		  break;

	  case READ_OWNER:
	  case READ_COPY:
		  obj_state = OBJ_STATE(obj_entry);
		  if (!(msg->flags & KDDM_NO_DATA))
			  dont_insert = 1;
		  break;

	  default:
		  STATE_MACHINE_ERROR (msg->set_id, msg->objid, obj_entry);
		  BUG();
	}

	if (!(msg->flags & KDDM_NO_DATA)) {
		kddm_change_obj_state (set, obj_entry, msg->objid,
				       INV_FILLING);

		/* Mark the object frozen to avoid nastly things while
		 * we release the lock */
		set_object_frozen(obj_entry);
		unlock_obj_entry(obj_entry);

		res = kddm_io_alloc_object (obj_entry, set, msg->objid);
		BUG_ON(res != 0);

		kddm_io_import_object (desc, set, obj_entry, msg->objid,
				       msg->flags);

		lock_obj_entry(obj_entry);
		object_clear_frozen(obj_entry, set);

		if (obj_state == WAIT_ACK_INV) {
			if (OBJ_EXCLUSIVE (obj_entry))
				/* Missing ACKs has been received during the
				 * import
				 */
				obj_state = WRITE_OWNER;
			else
				/* We are still waiting for ACKs... Don't
				 * insert the object until all ACKs has been
				 * received. Insert is done in the ACK receive
				 * function.
				 */
				dont_insert = 1;
		}

		if (dont_insert) {
			kddm_change_obj_state (set, obj_entry, msg->objid,
					       obj_state);
		}
		else
			kddm_insert_object (set, msg->objid, obj_entry,
					    obj_state);
	}

	put_kddm_obj_entry(set, obj_entry, msg->objid);

	if (msg->flags & KDDM_SYNC_OBJECT) {
		res = kddm_io_sync_object(obj_entry, set, msg->objid);
		rpc_pack_type(desc, res);
	}

	return;
}



/** Handle no object request.
 *  @author Renaud Lottiaux
 *
 *  @param sender  Node sending the request.
 *  @param msg     Message received from the requesting node.
 */
int __handle_no_object (kerrighed_node_t sender,
			void *_msg)
{
	msg_server_t *msg = _msg;
	struct kddm_obj *obj_entry;
	struct kddm_set *set;

	BUG_ON (sender < 0 || sender > KERRIGHED_MAX_NODES);

	obj_entry = get_alloc_kddm_obj_entry (msg->ns_id, msg->set_id,
					      msg->objid, &set);

	if (object_frozen (obj_entry)) {
		queue_event (__handle_no_object, sender, set, obj_entry,
			     msg->objid, msg, sizeof (msg_server_t));

		goto exit;
	}

	ADD_TO_SET(RMSET(obj_entry), sender);

	switch (OBJ_STATE(obj_entry)) {
	  case WAIT_OBJ_READ:
	  case WAIT_OBJ_WRITE:
		  if (msg->flags ||
		      (kddm_io_default_owner(set, msg->objid) ==
		       kerrighed_node_id))
			  kddm_change_obj_state (set, obj_entry, msg->objid,
						 INV_OWNER);
		  else
			  kddm_change_obj_state (set, obj_entry, msg->objid,
						 INV_COPY);

		  wake_up_on_wait_object (obj_entry, set);

		  kddm_io_remove_object_and_unlock (obj_entry, set,
						    msg->objid, NULL);
		  goto exit_no_unlock;

	  case INV_OWNER:
		  wake_up_on_wait_object (obj_entry, set);
		  break;

	  default:
		  STATE_MACHINE_ERROR (msg->set_id, msg->objid, obj_entry);
		  break;
	}

exit:
	put_kddm_obj_entry(set, obj_entry, msg->objid);

exit_no_unlock:
	return 0;
}

void handle_no_object (struct rpc_desc* desc,
		      void *_msg, size_t size){
	__handle_no_object(desc->client, _msg);
};


/** Handle a write access receive.
 *  @author Renaud Lottiaux
 *
 *  @param sender  Node sending the write access.
 *  @param msg     Message received.
 */
void handle_receive_write_access (struct rpc_desc* desc,
				  void *_msg, size_t size)
{
	msg_injection_t *msg = _msg;
	struct kddm_obj *obj_entry;
	struct kddm_set *set;

	BUG_ON (desc->client < 0 || desc->client > KERRIGHED_MAX_NODES);

	obj_entry = get_alloc_kddm_obj_entry (msg->ns_id, msg->set_id,
					      msg->objid, &set);

	krgnodes_copy(obj_entry->master_obj.rmset, msg->owner_info.rmset);

	switch (OBJ_STATE(obj_entry)) {
	  case WAIT_OBJ_WRITE:
		  BUG_ON (obj_entry->object == NULL);
		  ADD_TO_SET(COPYSET(obj_entry), desc->client);
		  merge_ack_set(COPYSET(obj_entry), &msg->owner_info.copyset);
		  ADD_TO_SET(COPYSET(obj_entry), kerrighed_node_id);
		  if (OBJ_EXCLUSIVE2 (COPYSET(obj_entry))) {
			  kddm_change_obj_state (set, obj_entry, msg->objid,
						 WRITE_OWNER);
			  wake_up_on_wait_object (obj_entry, set);
		  }
		  else
			  kddm_change_obj_state (set, obj_entry, msg->objid,
						 WAIT_ACK_WRITE);
		  break;

	  default:
		  STATE_MACHINE_ERROR (msg->set_id, msg->objid, obj_entry);
		  break;
	}

	put_kddm_obj_entry(set, obj_entry, msg->objid);

	return;
}



/** Handle an object copy request.
 *  @author Renaud Lottiaux
 *
 *  @param sender    Node sending the request.
 *  @param msg       Message received from the requesting node.
 */
static inline int __handle_object_copy_req (kerrighed_node_t sender,
					    void *_msg)
{
	msg_server_t *msg = _msg;
	struct kddm_obj *obj_entry;
	struct kddm_set *set;
	int request_type = msg->flags & KDDM_SET_REQ_TYPE;
	int send_ownership = msg->flags & KDDM_SEND_OWNERSHIP;
	int r;

	BUG_ON (sender < 0 || sender > KERRIGHED_MAX_NODES);

	obj_entry = get_kddm_obj_entry (msg->ns_id, msg->set_id,
					msg->objid, &set);

	/* First, check for NULL obj_entry case */
	if (obj_entry == NULL) {
		if (!I_AM_DEFAULT_OWNER(set, msg->objid)) {
			forward_object_server_msg (obj_entry, set,
						   REQ_OBJECT_COPY, msg);
			goto exit_no_unlock;
		}

		if ((msg->flags & KDDM_NO_FT_REQ) && !send_ownership) {
			send_no_object (set, obj_entry, msg->objid,
					msg->reply_node, send_ownership);
			goto exit_no_unlock;
		}

		obj_entry = get_alloc_kddm_obj_entry (msg->ns_id, msg->set_id,
						      msg->objid, &set);
	}

	if (object_frozen_or_pinned (obj_entry)) {
		if (msg->flags & KDDM_TRY_GRAB)
			send_no_object (set, obj_entry, msg->objid,
					msg->reply_node, send_ownership);
		else
			queue_event (__handle_object_copy_req, sender, set,
				     obj_entry, msg->objid, msg,
				     sizeof (msg_server_t));
		goto exit;
	}

	/* First checks if we are in a loop-back request. Some of them can be
	 * valid requests due to some corner cases in the protocol.
	 */
	if (msg->reply_node != kerrighed_node_id)
		goto regular_case;

	switch (OBJ_STATE(obj_entry)) {
	  case WAIT_OBJ_READ:
	  case WAIT_OBJ_WRITE:
		  /* The following test prevents from the answer of a node
		   * which has just removed its copy and now believes we are
		   * the new owner. And this is true, we are the new owner
		   * of a new object we have to create.
		   */
		  if (msg->flags & KDDM_NO_FT_REQ) {
			  kddm_change_obj_state (set, obj_entry, msg->objid,
						 INV_OWNER);
			  wake_up_on_wait_object (obj_entry, set);
			  break;
		  }

		  r = object_first_touch (set, obj_entry, msg->objid,
					  WRITE_OWNER, msg->flags);
		  if (r)
			  goto first_touch_error;
		  break;

	  case INV_COPY:
	  case READ_COPY:
	  case READ_OWNER:
	  case WRITE_OWNER:
	  case WRITE_GHOST:
	  case WAIT_ACK_INV:
	  case WAIT_OBJ_RM_ACK:
	  case WAIT_OBJ_RM_ACK2:
	  case WAIT_CHG_OWN_ACK:
	  case WAIT_OBJ_RM_DONE:
	  case WAIT_ACK_WRITE:
	  case INV_OWNER:
	  case INV_FILLING:
		  /* Here, we receive a copy request following a flush on the
		   * sending node. Our copy request has been served by the
		   * flush. We can ignore this message.
		   */
		  break;

	  default:
		  STATE_MACHINE_ERROR (msg->set_id, msg->objid, obj_entry);
		  break;
	}

	goto exit;

	/* Now, the regular cases : no loop back request */

regular_case:
	switch (OBJ_STATE(obj_entry)) {
	  case WAIT_OBJ_READ:
	  case INV_COPY:
	  case READ_COPY:
		  /* Shorten the prob owner chain on a write request */
/*		  if (request_type == KDDM_OBJ_COPY_ON_WRITE) */
/*			  change_prob_owner(obj_entry, msg->new_owner); */

		  forward_object_server_msg (obj_entry, set,
					     REQ_OBJECT_COPY, msg);
		  break;

	  case INV_OWNER:
		  if (msg->flags & KDDM_NO_FT_REQ) {
			  send_no_object (set, obj_entry, msg->objid,
					  msg->reply_node, send_ownership);
			  break;
		  }

		  if (!kddm_ft_linked (set))
			  /* The object can be created on the faulting node */
			  send_back_object_first_touch (set, obj_entry,
							msg->objid,
							msg->reply_node,
							msg->flags,
							SEND_BACK_FIRST_TOUCH);
		  else {
			  /* The object can be created on the local node  */
			  if (request_type == KDDM_OBJ_COPY_ON_WRITE) {
				  /* The object can be created on the local node */
				  r = object_first_touch_no_wakeup (
					  set, obj_entry, msg->objid,
					  WRITE_OWNER, msg->flags);
				  if (r)
					  goto first_touch_error;
				  obj_entry = send_copy_on_write_and_inv(
					  set, obj_entry, msg->objid,
					  msg->reply_node, 0);

				  goto exit_no_unlock;
			  }
			  else {
				  r = object_first_touch (
					  set, obj_entry, msg->objid,
					  READ_OWNER, msg->flags);
				  if (r)
					  goto first_touch_error;
				  goto send_copy;
			  }
		  }
		  break;

	  case WRITE_GHOST:
		  obj_entry = send_copy_on_write_and_inv(
			  set, obj_entry, msg->objid,
			  msg->reply_node, 0);

		  goto exit_no_unlock;

	  case WRITE_OWNER:
		  if (request_type == KDDM_OBJ_COPY_ON_READ) {
			  kddm_change_obj_state (set, obj_entry, msg->objid,
						 READ_OWNER);
			  goto send_copy;
		  }
		  else {
			  obj_entry = send_copy_on_write_and_inv(
				  set, obj_entry, msg->objid,
				  msg->reply_node, 0);

			  goto exit_no_unlock;
		  }

	  case READ_OWNER:

		  if (request_type == KDDM_OBJ_COPY_ON_READ) {
send_copy:
			  /* Read copy request */

			  send_copy_on_read (set, obj_entry, msg->objid,
					     msg->reply_node, 0);
			  break;
		  }

		  /* Write copy request */

		  change_prob_owner (obj_entry, msg->reply_node);
		  request_copies_invalidation (set, obj_entry,
					       msg->objid,
					       msg->reply_node);

		  if (NODE_IN_SET (COPYSET(obj_entry), msg->reply_node))
			  transfer_write_access_and_unlock (
				  set, obj_entry, msg->objid,
				  msg->reply_node,
				  &obj_entry->master_obj);
		  else {
			  obj_entry = send_copy_on_write_and_inv(
				  set, obj_entry, msg->objid,
				  msg->reply_node, 0);
		  }

		  goto exit_no_unlock;

	  case WAIT_OBJ_RM_ACK:
	  case WAIT_OBJ_RM_ACK2:
	  case WAIT_OBJ_RM_DONE:
	  case WAIT_CHG_OWN_ACK:
	  case WAIT_ACK_WRITE:
	  case WAIT_OBJ_WRITE:
	  case WAIT_ACK_INV:
	  case INV_FILLING:
		  queue_event (__handle_object_copy_req, sender, set,
			       obj_entry, msg->objid, msg,
			       sizeof (msg_server_t));
		  break;

	  default:
		  STATE_MACHINE_ERROR (msg->set_id, msg->objid, obj_entry);
		  break;
	}

exit:
	put_kddm_obj_entry(set, obj_entry, msg->objid);

exit_no_unlock:
	return 0;

first_touch_error:
	BUG_ON (r != ENODATA);

	BUG_ON (msg->reply_node == kerrighed_node_id);
	send_no_object (set, obj_entry, msg->objid, msg->reply_node,
			0 /* send ownership */);
	goto exit;
}

void handle_object_copy_req (struct rpc_desc* desc,
			    void *_msg, size_t size){
	__handle_object_copy_req(desc->client, _msg);
}

/** Handle an object remove request on the manager node.
 *  @author Renaud Lottiaux
 *
 *  @param sender    Node sending the request.
 *  @param msg       Message received from the requesting node.
 */
static inline
int __handle_object_remove_to_mgr_req (kerrighed_node_t sender,
				       void *_msg)
{
	msg_server_t *msg = _msg;
	struct kddm_set *set;
	struct kddm_obj *obj_entry;
	int err = 0;

	obj_entry = get_alloc_kddm_obj_entry (msg->ns_id, msg->set_id,
					      msg->objid, &set);

	if (object_frozen_or_pinned(obj_entry)) {
		queue_event (__handle_object_remove_to_mgr_req, sender, set,
			     obj_entry, msg->objid, msg,
			     sizeof (msg_server_t));
		goto exit;
	}

	switch (OBJ_STATE(obj_entry)) {
	  case INV_COPY:
	  case READ_COPY:
	  case WAIT_OBJ_READ:
	  case WAIT_OBJ_WRITE:
		  forward_object_server_msg (obj_entry, set,
					     REQ_OBJECT_REMOVE_TO_MGR, msg);
		  break;

	  case WAIT_OBJ_RM_ACK:
	  case WAIT_OBJ_RM_ACK2:
	  case WAIT_OBJ_RM_DONE:
		  err = -EALREADY;
		  break;

	  case WAIT_ACK_WRITE:
	  case WAIT_CHG_OWN_ACK:
	  case WAIT_ACK_INV:
	  case INV_FILLING:
		  queue_event (__handle_object_remove_to_mgr_req, sender, set,
			       obj_entry, msg->objid, msg,
			       sizeof (msg_server_t));
		  break;

	  case INV_OWNER:
	  case READ_OWNER:
	  case WRITE_OWNER:
	  case WRITE_GHOST:
		  request_copies_remove(set, obj_entry,
					msg->objid,
					msg->reply_node);
		  send_remove_object_done(set, msg->objid,
					  msg->reply_node, RMSET(obj_entry));

		  destroy_kddm_obj_entry(set, obj_entry,
					 msg->objid, 1);
		  goto exit_no_unlock;

	  default:
		  STATE_MACHINE_ERROR (msg->set_id, msg->objid, obj_entry);
		  break;
	}

exit:
	put_kddm_obj_entry(set, obj_entry, msg->objid);

exit_no_unlock:
	return err;
}

void handle_object_remove_to_mgr_req (struct rpc_desc* desc,
				     void *_msg, size_t size){
	__handle_object_remove_to_mgr_req(desc->client, _msg);
};


/** Handle an object request response which is : make a local first touch.
 *  @author Renaud Lottiaux
 *
 *  @param msg  Message received from the requesting node.
 */
void handle_send_back_first_touch_req (struct rpc_desc* desc,
				       void *_msg, size_t size)
{
	msg_server_t *msg = _msg;
	struct kddm_set *set;
	struct kddm_obj *obj_entry;

	BUG_ON (desc->client < 0 || desc->client > KERRIGHED_MAX_NODES);

	obj_entry = get_kddm_obj_entry (msg->ns_id, msg->set_id,
					msg->objid, &set);

	switch (OBJ_STATE(obj_entry)) {
	  case WAIT_OBJ_READ:
	  case WAIT_OBJ_WRITE:
		  BUG_ON (msg->reply_node == kerrighed_node_id);

		  ADD_TO_SET(RMSET(obj_entry), desc->client);
		  if (object_first_touch(set, obj_entry, msg->objid,
					 WRITE_OWNER, msg->flags) != 0)
			  BUG();
		  break;

	  default:
		  STATE_MACHINE_ERROR (msg->set_id, msg->objid, obj_entry);
		  break;
	}
	put_kddm_obj_entry(set, obj_entry, msg->objid);

	return;
}


/** Handle the change of an object default owner.
 *  @author Renaud Lottiaux
 *
 *  @param msg  Message received from the requesting node.
 */
static int handle_change_prob_owner_req(struct rpc_desc* desc,
					void *_msg, size_t size)
{
	msg_server_t *msg = _msg;
	struct kddm_obj *obj_entry;
	struct kddm_set *set;

	BUG_ON (desc->client < 0 || desc->client > KERRIGHED_MAX_NODES);

	obj_entry = get_alloc_kddm_obj_entry_lock_free (msg->ns_id,
							msg->set_id,
							msg->objid, &set);

	change_prob_owner(obj_entry, msg->new_owner);

	if (OBJ_STATE(obj_entry) == INV_OWNER)
		kddm_change_obj_state(set, obj_entry, msg->objid, INV_COPY);

	put_kddm_obj_entry(set, obj_entry, msg->objid);

	return 0;
};


/* Object Server Initialisation */

void object_server_init ()
{
	object_server = rpc_synchro_new(1, "object server", 1);
	object_server_may_block = rpc_synchro_new(1, "object srv may block", 1);

	/***  Init the object serveur  ***/

	__rpc_register(REQ_OBJECT_COPY,
		       RPC_TARGET_NODE, RPC_HANDLER_KTHREAD_VOID,
		       object_server, handle_object_copy_req, 0);

	__rpc_register(REQ_OBJECT_REMOVE,
		       RPC_TARGET_NODE, RPC_HANDLER_KTHREAD_VOID,
		       object_server, handle_object_remove_req, 0);

	__rpc_register(REQ_OBJECT_REMOVE_TO_MGR,
		       RPC_TARGET_NODE, RPC_HANDLER_KTHREAD_VOID,
		       object_server, handle_object_remove_to_mgr_req, 0);

	__rpc_register(SEND_BACK_FIRST_TOUCH,
		       RPC_TARGET_NODE, RPC_HANDLER_KTHREAD_VOID,
		       object_server_may_block, handle_send_back_first_touch_req, 0);

	__rpc_register(REQ_OBJECT_INVALID,
		       RPC_TARGET_NODE, RPC_HANDLER_KTHREAD_VOID,
		       object_server, handle_object_invalidation, 0);

	__rpc_register(INVALIDATION_ACK,
		       RPC_TARGET_NODE, RPC_HANDLER_KTHREAD_VOID,
		       object_server, handle_invalidation_ack, 0);

	__rpc_register(REMOVE_ACK,
		       RPC_TARGET_NODE, RPC_HANDLER_KTHREAD_VOID,
		       object_server, handle_remove_ack, 0);

	__rpc_register(REMOVE_ACK2,
		       RPC_TARGET_NODE, RPC_HANDLER_KTHREAD_VOID,
		       object_server_may_block, handle_remove_ack2, 0);

	__rpc_register(REMOVE_DONE,
		       RPC_TARGET_NODE, RPC_HANDLER_KTHREAD_VOID,
		       object_server, handle_remove_done, 0);

	__rpc_register(SEND_OWNERSHIP,
		       RPC_TARGET_NODE, RPC_HANDLER_KTHREAD_VOID,
		       object_server, handle_send_ownership_req, 0);

	__rpc_register(CHANGE_OWNERSHIP_ACK,
		       RPC_TARGET_NODE, RPC_HANDLER_KTHREAD_VOID,
		       object_server, handle_change_ownership_ack, 0);

	__rpc_register(OBJECT_SEND,
		       RPC_TARGET_NODE, RPC_HANDLER_KTHREAD_VOID,
		       object_server, handle_object_receive, 0);

	__rpc_register(SEND_WRITE_ACCESS,
		       RPC_TARGET_NODE, RPC_HANDLER_KTHREAD_VOID,
		       object_server, handle_receive_write_access, 0);

	__rpc_register(NO_OBJECT_SEND,
		       RPC_TARGET_NODE, RPC_HANDLER_KTHREAD_VOID,
		       object_server, handle_no_object, 0);

	rpc_register_int(KDDM_CHANGE_PROB_OWNER, handle_change_prob_owner_req,
			 0);
}



/* Object Server Finalization */

void object_server_finalize ()
{
}
