/** KDDM find object.
 *  @file kddm_find_object.h
 *
 *  Definition of KDDM interface.
 *  @author Renaud Lottiaux
 */

#ifndef __KDDM_FIND_OBJECT__
#define __KDDM_FIND_OBJECT__

#include <kddm/kddm_set.h>



/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/



/** Check the presence of a given object in local physical memory. */
void *kddm_find_object (struct kddm_ns *ns, kddm_set_id_t set_id,
			objid_t objid);

void *_kddm_find_object (struct kddm_set *set, objid_t objid);

static inline void *_kddm_find_object_raw (struct kddm_set *set, objid_t objid)
{
	struct kddm_obj *obj_entry;
	void *obj = NULL;

	kddm_lock_obj_table(set);
	obj_entry = set->ops->lookup_obj_entry(set, objid);
	kddm_unlock_obj_table(set);
	if (obj_entry)
		obj = obj_entry->object;

	return obj;
}

#endif
