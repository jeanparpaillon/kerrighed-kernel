/** KDDM set object.
 *  @file kddm_set_object.h
 *
 *  Definition of KDDM interface.
 *  @author Renaud Lottiaux
 */

#ifndef __KDDM_SET_OBJECT__
#define __KDDM_SET_OBJECT__

#include <kddm/kddm_set.h>


/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/



/** Set the initial value of an object. */
int _kddm_set_object_state(struct kddm_set *set, objid_t objid, void *object,
			   kddm_obj_state_t state);

int kddm_set_object_state(struct kddm_ns *ns, kddm_set_id_t set_id,
			  objid_t objid, void *object, kddm_obj_state_t state);

int _kddm_set_object(struct kddm_set *set, objid_t objid, void *object);

int kddm_set_object(struct kddm_ns *ns, kddm_set_id_t set_id, objid_t objid,
		    void *object);

#endif
