


/** KDDM remove object.
 *  @file kddm_remove_object.h
 *
 *  Definition of KDDM interface.
 *  @author Renaud Lottiaux
 */

#ifndef __KDDM_REMOVE_OBJECT__
#define __KDDM_REMOVE_OBJECT__

#include <kddm/kddm_set.h>


/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/



/** Remove an object from a kddm set cluster wide */
int kddm_remove_object(struct kddm_ns *ns, kddm_set_id_t set_id,
		       objid_t objid);

int _kddm_remove_object(struct kddm_set *set, objid_t objid);

int kddm_remove_frozen_object(struct kddm_ns *ns, kddm_set_id_t set_id,
			      objid_t objid);

int _kddm_remove_frozen_object(struct kddm_set *set, objid_t objid);

#endif
