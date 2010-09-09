/** KDDM put object
 *  @file kddm_put_object.c
 *
 *  Implementation of KDDM put object function.
 *
 *  Copyright (C) 2001-2006, INRIA, Universite de Rennes 1, EDF.
 *  Copyright (C) 2006-2007, Renaud Lottiaux, Kerlabs.
 */
#include <linux/module.h>

#include <kddm/kddm.h>
#include "protocol_action.h"


/** Release an object which has been acquired by a get, grab or find.
 *  @author Renaud Lottiaux
 *
 *  @param set        KDDM set hosting the object.
 *  @param obj_entry  Object entry of the object to put.
 *  @param objid      Identifier of the object to put.
 *
 *  @return           Pointer to the object if it is present in memory,
 *                    NULL otherwise.
 */
void _kddm_put_object(struct kddm_set *set,
		      objid_t objid)
{
	struct kddm_obj *obj_entry;
	int pending = 0;

	obj_entry = __get_kddm_obj_entry(set, objid);
	if (!obj_entry)
		return;

	/* The object is not frozen, nothing to do */
	if (!object_frozen(obj_entry))
		goto exit;

	kddm_io_put_object(obj_entry, set, objid);
	object_clear_frozen(obj_entry, set);
	if (TEST_OBJECT_PENDING(obj_entry)) {
		CLEAR_OBJECT_PENDING(obj_entry);
		pending = 1;
	}

exit:
	put_kddm_obj_entry(set, obj_entry, objid);
	if (pending)
		flush_kddm_event(set, objid);
}
EXPORT_SYMBOL(_kddm_put_object);



void kddm_put_object(struct kddm_ns *ns, kddm_set_id_t set_id, objid_t objid)
{
	struct kddm_set *set;

	set = _find_get_kddm_set (ns, set_id);
	_kddm_put_object(set, objid);
	put_kddm_set(set);
}
EXPORT_SYMBOL(kddm_put_object);
