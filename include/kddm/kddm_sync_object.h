/** KDDM sync object.
 *  @file kddm_sync_object.h
 *
 *  Definition of KDDM interface.
 *  @author Renaud Lottiaux
 */

#ifndef __KDDM_SYNC_OBJECT__
#define __KDDM_SYNC_OBJECT__

#include <kddm/kddm_set.h>


/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/



/** Sync an object from local memory */
int kddm_sync_frozen_object(struct kddm_ns *ns, kddm_set_id_t set_id,
			    objid_t objid);

int _kddm_sync_frozen_object(struct kddm_set *set, objid_t objid);

#endif
