/** KDDM flush object.
 *  @file kddm_flush_object.h
 *
 *  Definition of KDDM interface.
 *  @author Renaud Lottiaux
 */

#ifndef __KDDM_FLUSH_OBJECT__
#define __KDDM_FLUSH_OBJECT__

#include <kddm/kddm_set.h>


/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/



/** Flush an object from local memory */
int kddm_flush_object(struct kddm_ns *ns, kddm_set_id_t set_id, objid_t objid,
		      kerrighed_node_t dest);

int _kddm_flush_object(struct kddm_set *set, objid_t objid,
		       kerrighed_node_t dest);

/** Flush all objects of a KDDM set from local memory */
void kddm_flush_set(struct kddm_ns *ns, kddm_set_id_t set_id,
		    int(*f)(struct kddm_set *, objid_t, struct kddm_obj *,
			    void*), void *data);

void _kddm_flush_set(struct kddm_set *set,
		    int(*f)(struct kddm_set *, objid_t, struct kddm_obj *,
			    void*), void *data);

#endif
