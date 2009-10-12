/*
 *  Copyright (C) 2006-2007, Pascal Gallard, Kerlabs.
 */

#include <linux/wait.h>
#include <linux/list.h>
#include <linux/kernel.h>
#include <kerrighed/sys/types.h>
#include <kerrighed/krgnodemask.h>
#include <kerrighed/krginit.h>
#include <linux/hashtable.h>
#include <linux/cluster_barrier.h>

#include <net/krgrpc/rpcid.h>
#include <net/krgrpc/rpc.h>
#include <kerrighed/hotplug.h>
#include <kddm/kddm.h>
#include "protocol_action.h"

struct cluster_barrier *kddm_barrier;

extern krgnodemask_t krgnode_kddm_map;
extern kerrighed_node_t kddm_nb_nodes;
extern kerrighed_node_t __kddm_io_default_owner (struct kddm_set *set,
						 objid_t objid,
						 const krgnodemask_t *nodes,
						 int nr_nodes);


/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                NODE ADDITION                             *
 *                                                                          *
 *--------------------------------------------------------------------------*/

struct browse_add_param {
	struct kddm_set *set;
	krgnodemask_t new_nodes_map;
	kerrighed_node_t new_nb_nodes;
};

static int add_browse_objects(unsigned long objid,
			      void *_obj_entry,
			      void *_data)
{
	struct kddm_obj *obj_entry = (struct kddm_obj *)_obj_entry;
	kerrighed_node_t old_def_owner, new_def_owner;
	struct browse_add_param *param = _data;
	struct kddm_set *set = param->set;

	old_def_owner = kddm_io_default_owner (set, objid);
	new_def_owner = __kddm_io_default_owner(set, objid,
						&param->new_nodes_map,
						param->new_nb_nodes);

	if (new_def_owner == old_def_owner)
		goto done;

	switch (OBJ_STATE(obj_entry)) {
	case READ_OWNER:
	case WRITE_GHOST:
	case WRITE_OWNER:
	case WAIT_ACK_INV:
	case WAIT_ACK_WRITE:
	case WAIT_CHG_OWN_ACK:
		BUG_ON (get_prob_owner(obj_entry) != kerrighed_node_id);
		if (new_def_owner == kerrighed_node_id)
			break;
		/* Inform the new owner a copy already exist */
		request_change_prob_owner(set, objid, new_def_owner,
					  kerrighed_node_id);
		break;

	case INV_OWNER:
		/* Update the local default owner to the new one */
		change_prob_owner(obj_entry, new_def_owner);
		break;

	case INV_COPY:
	case READ_COPY:
	case WAIT_OBJ_READ:
	case WAIT_OBJ_WRITE:
	case WAIT_OBJ_RM_DONE:
		BUG_ON(get_prob_owner(obj_entry) == kerrighed_node_id);
		break;

	case WAIT_OBJ_RM_ACK:
		PANIC ("Case not yet managed\n");

	case INV_FILLING:
		BUG();

	default:
		STATE_MACHINE_ERROR (set->id, objid, obj_entry);
		break;
	}

done:
	return 0;
};

static void add_browse_sets(void *_set, void *_data)
{
	struct browse_add_param *param = _data;
	struct kddm_set *set = _set;

	BUG_ON(set->def_owner < 0);
	BUG_ON(set->def_owner > KDDM_MAX_DEF_OWNER);

	switch (set->def_owner) {
	case KDDM_RR_DEF_OWNER:
	case KDDM_CUSTOM_DEF_OWNER:
		param->set = set;
		__for_each_kddm_object(set, add_browse_objects, _data);
		break;

	case KDDM_UNIQUE_ID_DEF_OWNER:
		/* The unique_id default owners are hard-coded depending on
		 * object ids. Adding a node doesn't change anything. */
	default:
		/* The default owner is hard coded to a given node.
		 * Adding a node doesn't change anything for these cases.
		 */
		break;
	};

};

static void set_add(krgnodemask_t * vector)
{
	struct browse_add_param param;
        kerrighed_node_t node;

	if(__krgnode_isset(kerrighed_node_id, vector))
		rpc_enable(KDDM_CHANGE_PROB_OWNER);

	krgnodes_copy(param.new_nodes_map, krgnode_online_map);

	param.new_nb_nodes = kerrighed_nb_nodes;
	__for_each_krgnode_mask(node, vector) {
		if (!krgnode_online(node)) {
			krgnode_set(node, param.new_nodes_map);
			param.new_nb_nodes++;
		}
	};

	freeze_kddm();

	cluster_barrier(kddm_barrier, &param.new_nodes_map,
			__first_krgnode(&param.new_nodes_map));

	__hashtable_foreach_data(kddm_def_ns->kddm_set_table,
				 add_browse_sets, &param);

	cluster_barrier(kddm_barrier, &param.new_nodes_map,
			__first_krgnode(&param.new_nodes_map));

	kddm_nb_nodes = param.new_nb_nodes;
	krgnodes_copy(krgnode_kddm_map, param.new_nodes_map);

	unfreeze_kddm();

	if(!__krgnode_isset(kerrighed_node_id, vector))
		return;

	rpc_enable(REQ_OBJECT_COPY);
	rpc_enable(REQ_OBJECT_REMOVE);
	rpc_enable(REQ_OBJECT_REMOVE_TO_MGR);
	rpc_enable(SEND_BACK_FIRST_TOUCH);
	rpc_enable(REQ_OBJECT_INVALID);
	rpc_enable(INVALIDATION_ACK);
	rpc_enable(REMOVE_ACK);
	rpc_enable(REMOVE_ACK2);
	rpc_enable(REMOVE_DONE);
	rpc_enable(SEND_OWNERSHIP);
	rpc_enable(CHANGE_OWNERSHIP_ACK);
	rpc_enable(OBJECT_SEND);
	rpc_enable(SEND_WRITE_ACCESS);
	rpc_enable(NO_OBJECT_SEND);
}

/**
 *
 * Remove related part
 *
 **/

static int browse_remove(unsigned long objid, void *_obj_entry,
			 void *_data)
{
	struct kddm_obj *obj_entry = _obj_entry;
	struct kddm_set *kddm_set = (struct kddm_set *)_data;

	might_sleep();
	switch (OBJ_STATE(obj_entry)) {
	case READ_OWNER:
		up (&kddm_def_ns->table_sem);
		_kddm_flush_object(kddm_set, objid,
				   krgnode_next_online_in_ring(kerrighed_node_id));
		down (&kddm_def_ns->table_sem);
		return -1;
		break;

	case READ_COPY:
	case WRITE_GHOST:
	case WRITE_OWNER:
		// we have to flush this object
		_kddm_flush_object(kddm_set, objid,
				   krgnode_next_online_in_ring(kerrighed_node_id));
		break;

	case WAIT_ACK_INV:
	case WAIT_OBJ_RM_ACK:
		printk ("kddm_set_remove_cb: WAIT_ACK_INV: todo\n");
		break;

	case WAIT_ACK_WRITE:
	case WAIT_CHG_OWN_ACK:
	case WAIT_OBJ_READ:
	case WAIT_OBJ_WRITE:
		// here we have to check if there are some pending process...
		// and may be we kill them
		if (waitqueue_active
		    (&obj_entry->waiting_tsk))
			printk("we have some pending process in %lu %s (%x)\n",
			       objid,
			       STATE_NAME
			       (OBJ_STATE(obj_entry)),
			       OBJ_STATE(obj_entry));

	case INV_OWNER:
	case INV_COPY:
		break;

	case WAIT_OBJ_RM_DONE:
		PANIC ("Case not yet managed\n");

	default:
		STATE_MACHINE_ERROR
			(kddm_set->id,
			 objid, obj_entry);
		break;
	}

	return 0;
};

static void kddm_set_remove_cb(void *_kddm_set, void *_data)
{
	struct kddm_set *kddm_set = _kddm_set;

	__for_each_kddm_object(kddm_set, browse_remove, kddm_set);

};

static void set_remove(krgnodemask_t * vector)
{

	printk("set_remove...\n");
	return;

	down (&kddm_def_ns->table_sem);
	__hashtable_foreach_data(kddm_def_ns->kddm_set_table,
				 kddm_set_remove_cb, vector);
	up (&kddm_def_ns->table_sem);
};

/**
 *
 * Failure related part
 *
 **/

#if 0

extern krgnodemask_t failure_vector;

/*
 * comm transact: set_copyset
 */

static void handle_set_copyset(struct rpc_desc *desc)
{
	struct kddm_set *set;
	struct rpc_desc *new_desc;
	struct kddm_obj *obj_entry;
	kddm_set_id_t set_id;
	objid_t objid;
	krgnodemask_t map;
	kerrighed_node_t true_owner;
	kerrighed_node_t potential_owner;

	rpc_unpack_type(desc, set_id);
	rpc_unpack_type(desc, objid);
	rpc_unpack_type(desc, map);
	rpc_unpack_type(desc, true_owner);
	rpc_unpack_type(desc, potential_owner);

	// check if the object is available on this node
	// check if we are in the received copyset
	// yes: a new copyset has beed built (set myself as owner)
	// no: we are building a new copyset (update the copyset and forward the rq to the next node)
	// we have to look our probeOwner in order to decide if we relay the rq (and take care) or not

	// Is it my request ?
	if (krgnode_isset(kerrighed_node_id, map)) {
		// Yes it is (since I'm already in the copyset)

		obj_entry = _get_kddm_obj_entry(kddm_def_ns, set_id,
						objid, &set);

		// the object should be frozen... so we expect to be in READ_COPY
		BUG_ON(OBJ_STATE(obj_entry) != READ_COPY);

		// Is the true owner still alive ?
		if (true_owner == -1) {
			//No, it is dead: I migth have to become the new owner

			// May be there are some other applicant to this position...
			if (potential_owner == kerrighed_node_id) {
				// I'm the new owner
				kddm_change_obj_state(set, obj_entry, objid, READ_OWNER);
				change_prob_owner(obj_entry, kerrighed_node_id);

				krgnodes_copy(obj_entry->master_obj.copyset, map);

				/* TODO: have to check if the set is HARDLINKED */
				if (nth_online_krgnode(objid % kerrighed_nb_nodes) !=
				    kerrighed_node_id) {
					struct rpc_desc *desc;

					desc = rpc_begin(KDDM_ADVERTISE_OWNER,
							 nth_online_krgnode(objid % kerrighed_nb_nodes));
					rpc_pack_type(desc, set_id);
					rpc_pack_type(desc, objid);
					rpc_end(desc, 0);
				};

			} else {
				// There is another (better) applicant
				change_prob_owner(obj_entry, potential_owner);
			};
		} else {
			// Yes, It is: just update my prob_owner
			change_prob_owner(obj_entry, true_owner);
		};

		object_clear_frozen(obj_entry, set);
		put_kddm_obj_entry(set, obj_entry, objid);
	} else {

		set = _local_get_kddm_set(kddm_def_ns, set_id);

		// is this set availaible on this node ?
		if (!set)
			goto forward_rq;

		obj_entry = __get_kddm_obj_entry(set, objid);

		// is this object available on this node ?
		if (!obj_entry)
			goto put_set_forward_rq;

		if (I_AM_OWNER(obj_entry)) {
			// I'm the owner of this object: let everyboy knows about that
			true_owner = kerrighed_node_id;
			goto unlock_forward_rq;
		};

		// I'm not the owner
		if (true_owner != -1) {
			// The owner is known... just update my probOwner
			change_prob_owner(obj_entry, true_owner);
			goto unlock_forward_rq;
		};

		// The owner is unknown (until now), may be I could become the next one
		if (OBJ_STATE(obj_entry) == READ_COPY) {
			krgnode_set(kerrighed_node_id, map);

			// update our probOwner to potentiel owner
			change_prob_owner(obj_entry, potential_owner);

			// Check if local node is node a better potential owner
			// Here the potential owner is the one with the lowest id
			if (potential_owner < kerrighed_node_id) {
				potential_owner = kerrighed_node_id;
			};

			goto unlock_forward_rq;
		};

		// By default, if probOwner failed: update to potential_owner
		if(krgnode_isset(get_prob_owner(obj_entry), failure_vector))
			change_prob_owner(obj_entry, potential_owner);

	unlock_forward_rq:
		put_kddm_obj_entry(set, obj_entry, objid);

	put_set_forward_rq:
		put_kddm_set(set);

	forward_rq:
		// Forward the request
		new_desc = rpc_begin(krgnode_next_online_in_ring(kerrighed_node_id),
				     KDDM_COPYSET);
		rpc_pack_type(new_desc, set_id);
		rpc_pack_type(new_desc, objid);
		rpc_pack_type(new_desc, map);
		rpc_pack_type(new_desc, true_owner);
		rpc_pack_type(new_desc, potential_owner);
		rpc_end(new_desc, 0);
	};

};

/*
 * comm transact: advertise_owner
 */
static krgnodemask_t select_sync;

static void handle_select_owner(struct rpc_desc *desc)
{
	struct kddm_set *set;
	struct kddm_obj *obj_entry;
	kddm_set_id_t set_id;
	objid_t objid;
	krgnodemask_t copyset;
	kerrighed_node_t sender;
	int sync;

	rpc_unpack_type(desc, sender);
	rpc_unpack_type(desc, set_id);
	rpc_unpack_type(desc, objid);
	rpc_unpack_type(desc, copyset);
	rpc_unpack_type(desc, sync);

	if (sync != KERRIGHED_NODE_ID_NONE) {
		krgnode_set(sync, select_sync);

		// forward to the next node ?
		if (krgnode_next_online_in_ring(kerrighed_node_id) != sender)
			rpc_forward(desc, krgnode_next_online_in_ring(kerrighed_node_id));

		if (!krgnodes_equal(select_sync, krgnode_online_map)) {
			// We have to wait for another sync
			return;
		} else {
			// We received all the sync... we can continue the recovery mechanism
			down (&kddm_def_ns->table_sem);
			__hashtable_foreach_data(kddm_def_ns->kddm_set_table,
						 kddm_set_failure_cb,
						 &failure_vector);
			up (&kddm_def_ns->table_sem);

			return;
		};
	};

	// the struct kddm_setable lock is already held by the fct: kddm_set_failure
	set = __hashtable_find(kddm_def_ns->kddm_set_table, set_id);

	// is this set availaible on this node ?
	if (set != NULL) {

		obj_entry = __get_kddm_obj_entry(set, objid);

		// is this object available on this node ?
		if (obj_entry != NULL) {
			CLEAR_FAILURE_FLAG(obj_entry);
			change_prob_owner(obj_entry, sender);
			put_kddm_obj_entry(set, obj_entry, objid);
		};

	};

	// TODO: optimisation: ici on peut envoyer au suivant du copyset
	if (krgnode_next_online_in_ring(kerrighed_node_id) != sender) {
		struct rpc_desc *new_desc;

		new_desc = rpc_begin(KDDM_SELECT_OWNER,
				     krgnode_next_online_in_ring(kerrighed_node_id));
		rpc_pack_type(new_desc, sender);
		rpc_pack_type(new_desc, set_id);
		rpc_pack_type(new_desc, objid);
		rpc_pack_type(new_desc, copyset);
		rpc_pack_type(new_desc, sync);
		rpc_end(new_desc, 0);

	};

};

/**
 **
 ** Per kddm_set callback
 **
 **/
static int browse_clean_failure(unsigned long objid, void *_obj_entry,
				void *_data)
{
	struct kddm_obj *obj_entry = (struct kddm_obj *)_obj_entry;
	BUG_ON(!obj_entry);
	CLEAR_FAILURE_FLAG(obj_entry);
	return 0;
};

static void kddm_set_clean_failure_cb(void *_set, void *_data)
{
	struct kddm_set *set = _set;

	__for_each_kddm_object(set, browse_clean_failure, NULL);
};

static int browse_failure(unsigned long objid, void *_obj_entry,
			  void *_data)
{
	int correct_prob_owner = 0;
	struct kddm_set * set = (struct kddm_set *)_data;
	struct kddm_obj *obj_entry = (struct kddm_obj *)_obj_entry;

	if(TEST_FAILURE_FLAG(obj_entry))
		goto exit;

	if (kddm_ft_linked(set)) {
		if (!krgnode_online(get_prob_owner(obj_entry))){
			printk("browse_failure: TODO: set %ld is FT Linked\n",
			       set->id);
			change_prob_owner(obj_entry, kerrighed_node_id);
		}
	} else {
		if (krgnode_online(get_prob_owner(obj_entry)))
			correct_prob_owner = 1;

		if (!krgnode_online(get_prob_owner(obj_entry))
		    || get_prob_owner(obj_entry) == kerrighed_node_id)
			change_prob_owner(obj_entry,
			  nth_online_krgnode(objid % kerrighed_nb_nodes));

	};

	switch (OBJ_STATE(obj_entry)) {
	case READ_COPY:{
		struct rpc_desc *desc;
		krgnodemask_t copyset;
		kerrighed_node_t unknown = -1;

		// Does our prob-chain still valid ?
		if (correct_prob_owner)
			break;

		// No, it does not. We might have to choose a new owner

		// since we might be the new owner... freeze the object
		set_object_frozen(obj_entry, set);

		// start a ring-request in order to compute the new copyset
		krgnodes_clear(copyset);
		krgnode_set(kerrighed_node_id, copyset);

		desc = rpc_begin(KDDM_COPYSET,
				 krgnode_next_online_in_ring(kerrighed_node_id));
		rpc_pack_type(desc, set->id);
		rpc_pack_type(desc, objid);
		rpc_pack_type(desc, copyset);
		rpc_pack_type(desc, unknown);
		rpc_pack_type(desc, kerrighed_node_id);
		rpc_end(desc, 0);

		break;
	};

	case INV_OWNER:
	case READ_OWNER:
	case WRITE_GHOST:
	case WRITE_OWNER:{
		/* We just have to update the default probeOwner */

		if (get_prob_owner(obj_entry) != kerrighed_node_id) {
			struct rpc_desc *desc;

			desc = rpc_begin(KDDM_ADVERTISE_OWNER,
					 get_prob_owner(obj_entry));
			rpc_pack_type(desc, set->id);
			rpc_pack_type(desc, objid);
			rpc_end(desc, 0);
		};

		break;
	};

	case INV_COPY:
		break;

	case WAIT_ACK_INV:
		printk("kddm_set_failure_cb: WAIT_ACK_INV: todo\n");
		// we are waiting for the ack of an invalidation.
		// if the dest is a fail-node, we can just discard this rq silently
		break;

	case WAIT_OBJ_RM_ACK:
		printk("kddm_set_failure_cb: WAIT_OBJ_RM_ACK: todo\n");
		break;

	case WAIT_OBJ_RM_ACK2:
		printk("kddm_set_failure_cb: WAIT_OBJ_RM_ACK2: todo\n");
		break;

	case WAIT_ACK_WRITE:
	case WAIT_CHG_OWN_ACK:
	case WAIT_OBJ_READ:
	case WAIT_OBJ_WRITE:
		// we don't have the object and no one claim for it... destroy
		SET_FAILURE_FLAG(obj_entry);

		// we have some stuff waiting for unreachable object... destroy
		if (waitqueue_active(&obj_entry->waiting_tsk)){
			wait_queue_t *wait;

			wait = list_entry(obj_entry->waiting_tsk.task_list.next,
					  wait_queue_t, task_list);
			printk("we have some pending processes in %lu (%ld) "
			       "%s (%x)\n",
			       objid, set->id,
			       STATE_NAME(OBJ_STATE(obj_entry)),
			       OBJ_STATE(obj_entry));

			wake_up(&obj_entry->waiting_tsk);
		};
		break;

	default:
		STATE_MACHINE_ERROR(set->id, objid, obj_entry);
		break;
	};

exit:
	return 0;
};

static void kddm_set_failure_cb(void *_set, void *_data)
{
	struct kddm_set *set = _set;

	__for_each_kddm_object(set, browse_failure, set);
};

static int browse_select_owner(objid_t objid, void *_obj_entry,
			       void *_data)
{
	krgnodemask_t *vector_fail = _data;
	struct kddm_obj * obj_entry = (struct kddm_obj *)_obj_entry;

	BUG_ON(!vector_fail);

	if (I_AM_OWNER(obj_entry)) {
		kerrighed_node_t node;

		__for_each_krgnode_mask(node, vector_fail){
			REMOVE_FROM_SET(COPYSET(obj_entry), node);
		};

	};

	return 0;
};

static void kddm_set_select_owner_cb(void *_set, void *_data)
{
	struct kddm_set *set = _set;

	__for_each_kddm_object(set, browse_select_owner, _data);
};

/* set_failure
 * Handle the kddm recovery mechanism
 * 1. Stop ownership/copyset management of the object
 * 2. Clean the recovery information (may be from a previous recovery) of each object
 * 3. Prepare to receive ownership advertisement
 * 4. Advertise to every nodes each object we own
 * 5. Global synchro (in order to be sure that every node had sent its ownership)
 * 6. Restart ownership management
 * 7. Clean the object that loose the owner
 *    (try to elect a new ownership, destroy non correctible entries, SEGFAULT corresponding processes)
 */
static void set_failure(krgnodemask_t * vector)
{
	struct rpc_desc *desc;
	objid_t objid = 0;
	kddm_set_id_t set_id = 0;
	int sync = kerrighed_node_id;
	krgnodemask_t v;

	down (&kddm_def_ns->table_sem);

	__hashtable_foreach_data(kddm_def_ns->kddm_set_table,
				 kddm_set_clean_failure_cb, vector);

	krgnode_set(kerrighed_node_id, select_sync);

	__hashtable_foreach_data(kddm_def_ns->kddm_set_table,
				 kddm_set_select_owner_cb, vector);

	printk("TODO: we MUST lock creation/destruction of kddm_set during"
	       "the recovery step and we should use read/write lock\n");
	up (&kddm_def_ns->table_sem);

	desc = rpc_begin(KDDM_SELECT_OWNER,
			 krgnode_next_online_in_ring(kerrighed_node_id));
	rpc_pack_type(desc, kerrighed_node_id);
	rpc_pack_type(desc, set_id);
	rpc_pack_type(desc, objid);
	rpc_pack_type(desc, v);
	rpc_pack_type(desc, sync);
	rpc_end(desc, 0);

};

#endif

/**
 *
 * Notifier related part
 *
 */

static int kddm_notification(struct notifier_block *nb, hotplug_event_t event,
			     void *data){
	struct hotplug_context *ctx;
	struct hotplug_node_set *node_set;

	switch(event){
	case HOTPLUG_NOTIFY_ADD:
		ctx = data;
		set_add(&ctx->node_set.v);
		break;
	case HOTPLUG_NOTIFY_REMOVE:
		node_set = data;
		set_remove(&node_set->v);
		break;
	case HOTPLUG_NOTIFY_FAIL:
		node_set = data;
//		set_failure(&node_set->v);
		break;
	default:
		break;
	}

	return NOTIFY_OK;
};

int kddm_hotplug_init(void){
	kddm_barrier = alloc_cluster_barrier(KDDM_HOTPLUG_BARRIER);
	BUG_ON (IS_ERR(kddm_barrier));

//	rpc_register(KDDM_COPYSET, handle_set_copyset, 0);
//	rpc_register(KDDM_SELECT_OWNER, handle_select_owner, 0);

	register_hotplug_notifier(kddm_notification, HOTPLUG_PRIO_KDDM);
	return 0;
};

void kddm_hotplug_cleanup(void){
};
