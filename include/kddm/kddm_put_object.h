/** KDDM put object.
 *  @file kddm_put_object.h
 *
 *  Definition of KDDM interface.
 *  @author Renaud Lottiaux
 */

#ifndef __KDDM_PUT_OBJECT__
#define __KDDM_PUT_OBJECT__

#include <kddm/kddm_set.h>



/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/



/** Release a kddm object acquired by a find, get or grab object. */

void kddm_put_object(struct kddm_ns *ns, kddm_set_id_t set_id, objid_t objid);

void _kddm_put_object(struct kddm_set *set, objid_t objid);

#endif
