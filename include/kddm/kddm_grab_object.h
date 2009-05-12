/** KDDM grab object.
 *  @file kddm_grab_object.h
 *
 *  Definition of KDDM interface.
 *  @author Renaud Lottiaux
 */

#ifndef __KDDM_GRAB_OBJECT__
#define __KDDM_GRAB_OBJECT__

#include <kddm/kddm_set.h>


/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/



/** Place a write copy of a given object in local physical memory. */
void *kddm_grab_object(struct kddm_ns *ns, kddm_set_id_t set_id, objid_t objid);

void *_kddm_grab_object(struct kddm_set *set, objid_t objid);

void *__kddm_grab_object(struct kddm_set *set, struct kddm_obj *obj_entry,
			 objid_t objid);

/** Asynchronous version of the grab_object function. */
void *async_kddm_grab_object(struct kddm_ns *ns, kddm_set_id_t set_id,
			     objid_t objid);

void *_async_kddm_grab_object(struct kddm_set *set, objid_t objid);

void *__async_kddm_grab_object(struct kddm_set *set,
			       struct kddm_obj *obj_entry, objid_t objid);

/** Place a existing copy of a given object in local physical memory. */
void *kddm_grab_object_no_ft(struct kddm_ns *ns, kddm_set_id_t set_id,
			     objid_t objid);

void *_kddm_grab_object_no_ft(struct kddm_set *set, objid_t objid);

void *__kddm_grab_object_no_ft(struct kddm_set *set,
			       struct kddm_obj *obj_entry, objid_t objid);

/** Place a existing copy of a given object in local physical memory. */
void *async_kddm_grab_object_no_ft(struct kddm_ns *ns, kddm_set_id_t set_id,
			     objid_t objid);

void *_async_kddm_grab_object_no_ft(struct kddm_set *set, objid_t objid);

void *__async_kddm_grab_object_no_ft(struct kddm_set *set,
				     struct kddm_obj *obj_entry,objid_t objid);

/** Prepare an object to be manually filled by the function called */
void *kddm_grab_object_manual_ft(struct kddm_ns *ns, kddm_set_id_t set_id,
				 objid_t objid);

void *_kddm_grab_object_manual_ft(struct kddm_set *set, objid_t objid);

void *__kddm_grab_object_manual_ft(struct kddm_set *set,
				   struct kddm_obj *obj_entry,
				   objid_t objid);

/** Place a existing copy of a given object in local physical memory. */
void *kddm_grab_object_no_lock(struct kddm_ns *ns, kddm_set_id_t set_id,
			       objid_t objid);

void *_kddm_grab_object_no_lock(struct kddm_set *set, objid_t objid);

void *__kddm_grab_object_no_lock(struct kddm_set *set,
				 struct kddm_obj *obj_entry, objid_t objid);

/** Place a existing copy of a given object in local physical memory. */
void *kddm_try_grab_object(struct kddm_ns *ns, kddm_set_id_t set_id,
			   objid_t objid);

void *_kddm_try_grab_object(struct kddm_set *set, objid_t objid);

void *__kddm_try_grab_object(struct kddm_set *set,
			     struct kddm_obj *obj_entry, objid_t objid);

void *_kddm_grab_object_cow(struct kddm_set *set, objid_t objid);

/** Generic grab function with free use of KDDM flags */
void *fkddm_grab_object(struct kddm_ns *ns, kddm_set_id_t set_id,
			objid_t objid, int flags);

#endif
