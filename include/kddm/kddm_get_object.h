/** KDDM get object.
 *  @file kddm_get_object.h
 *
 *  Definition of KDDM interface.
 *  @author Renaud Lottiaux
 */

#ifndef __KDDM_GET_OBJECT__
#define __KDDM_GET_OBJECT__

#include <kddm/kddm_set.h>


/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/



/** Place a read-only copy of a given object in local physical memory. */
void *kddm_get_object(struct kddm_ns *ns, kddm_set_id_t set_id, objid_t objid);

void *_kddm_get_object(struct kddm_set *set, objid_t objid);



/** Asynchronous version of the get_object function. */
void *async_kddm_get_object(struct kddm_ns *ns, kddm_set_id_t set_id,
			    objid_t objid);

void *_async_kddm_get_object(struct kddm_set *set, objid_t objid);



/** Place a existing copy of a given object in local physical memory. */
void *kddm_get_object_no_ft(struct kddm_ns *ns, kddm_set_id_t set_id,
			    objid_t objid);

void *_kddm_get_object_no_ft(struct kddm_set *set, objid_t objid);



/** Prepare an object to be manually filled by the function called */
void *kddm_get_object_manual_ft(struct kddm_ns *ns, kddm_set_id_t set_id,
				objid_t objid);

void *_kddm_get_object_manual_ft(struct kddm_set *set, objid_t objid);



/** Place a existing copy of a given object in local physical memory. */
void *kddm_get_object_no_lock(struct kddm_ns *ns, kddm_set_id_t set_id,
			      objid_t objid);

void *_kddm_get_object_no_lock(struct kddm_set *set, objid_t objid);

/** Generic get functions with free use of KDDM flags */
void *fkddm_get_object(struct kddm_ns *ns, kddm_set_id_t set_id,
		       objid_t objid, int flags);

void *_fkddm_get_object(struct kddm_set *set, objid_t objid, int flags);

#endif
