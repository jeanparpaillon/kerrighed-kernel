/** Basic coherence protocol actions.
 *  @file protocol_action.h
 *
 *  @author Renaud Lottiaux
 */

#ifndef __PROTOCOL_ACTION__
#define __PROTOCOL_ACTION__

typedef int (*queue_event_handler_t) (kerrighed_node_t sender, void* msg);



/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/



/** Send object invalidation requests.
 *  @author Renaud Lottiaux
 */
void request_copies_invalidation (struct kddm_set *set,
				  struct kddm_obj *obj_entry, objid_t objid,
                                  kerrighed_node_t sender);

/** Send object remove requests.
 *  @author Renaud Lottiaux
 */
int request_copies_remove (struct kddm_set * set, struct kddm_obj *obj_entry,
			   objid_t objid, kerrighed_node_t sender);

/** Send object remove request to the object manager.
 *  @author Renaud Lottiaux
 */
void request_objects_remove_to_mgr (struct kddm_set * set,
				    struct kddm_obj * obj_entry,
				    objid_t objid);

/** Send an object write request for the given object.
 *  @author Renaud Lottiaux
 */
void request_object_on_write (struct kddm_set * set,
			      struct kddm_obj *obj_entry,
			      objid_t objid, int flags);

/** Send an object read request for the given object.
 *  @author Renaud Lottiaux
 */
void request_object_on_read (struct kddm_set * set, struct kddm_obj *obj_entry,
			     objid_t objid, int flags);

/** Send an object write copy to the given node.
 *  @author Renaud Lottiaux
 */
void send_copy_on_write (struct kddm_set *set, struct kddm_obj *obj_entry,
			 objid_t objid, kerrighed_node_t dest_node, int flags);

struct kddm_obj *send_copy_on_write_and_inv (struct kddm_set *set,
					     struct kddm_obj *obj_entry,
					     objid_t objid,
					     kerrighed_node_t dest_node,
					     int flags);


/** Send an object read copy to the given node.
 *  @author Renaud Lottiaux
 */
int send_copy_on_read (struct kddm_set *set, struct kddm_obj *obj_entry,
		       objid_t objid, kerrighed_node_t dest_node, int flags);

/** Send a "no object" anwser to the given node.
 *  @author Renaud Lottiaux
 */
void send_no_object (struct kddm_set * set, struct kddm_obj *obj_entry,
		     objid_t objid, kerrighed_node_t dest_node,
		     int send_ownership);

/** Send object write access to the given node.
 *  @author Renaud Lottiaux
 */
void transfer_write_access_and_unlock (struct kddm_set *set,
                                       struct kddm_obj *obj_entry,
				       objid_t objid,
				       kerrighed_node_t dest_node,
				       masterObj_t * master_info);

void merge_ack_set(krgnodemask_t *obj_set, krgnodemask_t *recv_set);

/** Send an object invalidation ack to the given node.
 *  @author Renaud Lottiaux
 */
void send_invalidation_ack (struct kddm_set *set, objid_t objid,
			    kerrighed_node_t dest_node);

/** Send an object remove ack to the given node.
 *  @author Renaud Lottiaux
 */
void send_remove_ack (struct kddm_set *set, objid_t objid,
		      kerrighed_node_t dest_node, int flags);
void send_remove_ack2 (struct kddm_set *set, objid_t objid,
		       kerrighed_node_t dest_node);

/** Send a global objects remove ack from the manager node to the given node.
 *  @author Renaud Lottiaux
 */
void send_remove_object_done (struct kddm_set *set, objid_t objid,
			      kerrighed_node_t dest_node,
			      krgnodemask_t *rmset);


/** Do an object first touch.
 *  @author Renaud Lottiaux
 */
int object_first_touch (struct kddm_set *set, struct kddm_obj *obj_entry,
			objid_t objid, kddm_obj_state_t objectState,
			int flags);
int object_first_touch_no_wakeup (struct kddm_set *set,
				  struct kddm_obj *obj_entry,objid_t objid,
                                  kddm_obj_state_t objectState, int flags);


/** Send back an object first touch request to the faulting node.
 *  @author Renaud Lottiaux
 */
void send_back_object_first_touch (struct kddm_set *set,
				   struct kddm_obj * obj_entry,
                                   objid_t objid, kerrighed_node_t dest_node,
                                   int flags, int req_type);

void send_change_ownership_req (struct kddm_set * set,
				struct kddm_obj *obj_entry, objid_t objid,
				kerrighed_node_t dest_node,
                                masterObj_t * master_info);

void ack_change_object_owner (struct kddm_set * set,
                              struct kddm_obj * obj_entry, objid_t objid,
			      kerrighed_node_t dest_node,
			      masterObj_t * master_info);

void queue_event (queue_event_handler_t event, kerrighed_node_t sender,
		  struct kddm_set *set, struct kddm_obj * obj_entry,
		  objid_t objid, void *dataIn, size_t data_size);

void flush_kddm_event(struct kddm_set *set, objid_t objid);
void freeze_kddm_event(struct kddm_set *set);
void unfreeze_kddm_event(struct kddm_set *set);

kerrighed_node_t choose_injection_node_in_copyset (struct kddm_obj * object);


int request_sync_object_and_unlock (struct kddm_set * set,
				    struct kddm_obj *obj_entry, objid_t objid,
				    kddm_obj_state_t new_state);


void request_change_prob_owner(struct kddm_set *set, struct kddm_obj *obj_entry,
			       objid_t objid, kerrighed_node_t dest_node,
			       kerrighed_node_t new_owner);

void request_force_update_def_owner_prob(struct kddm_set * set,
					 struct kddm_obj * obj_entry,
					 objid_t objid,
					 kerrighed_node_t new_def_owner);

void start_run_queue_thread (void);
void stop_run_queue_thread (void);

#endif // __PROTOCOL_ACTION__
