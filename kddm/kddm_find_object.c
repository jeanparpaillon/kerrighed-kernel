/** KDDM find object
 *  @file kddm_find_object.c
 *
 *  Implementation of KDDM find object function.
 *
 *  Copyright (C) 2001-2006, INRIA, Universite de Rennes 1, EDF.
 *  Copyright (C) 2006-2007, Renaud Lottiaux, Kerlabs.
 */
#include <linux/module.h>

#include <kddm/kddm.h>
#include "protocol_action.h"


/** Check the presence of a given object in local physical memory.
 *  @author Renaud Lottiaux
 *
 *  @param set        KDDM set hosting the object.
 *  @param obj_entry  Object_entry to lookup for.
 *  @param objid      Identifier of the requested object.
 *
 *  @return           Pointer to the object if it is present in memory,
 *                    NULL otherwise.
 */
void *_kddm_find_object (struct kddm_set *set,
			 objid_t objid)
{
	struct kddm_obj *obj_entry;
	void *object = NULL;

	obj_entry = __get_kddm_obj_entry(set, objid);

	if (obj_entry == NULL)
		return NULL;

	if (object_frozen(obj_entry)) {
		object = obj_entry->object;
	}

	switch (OBJ_STATE(obj_entry)) {
	case INV_OWNER:
	case INV_COPY:
	case INV_FILLING:
		/* No object... */
		break;

	case WAIT_ACK_INV:
	case WAIT_CHG_OWN_ACK:
		break;

	case WAIT_OBJ_RM_DONE:
	case WAIT_OBJ_RM_ACK:
	case WAIT_OBJ_RM_ACK2:
		/* There is an object but being destroyed... */
		break;

	case WAIT_OBJ_WRITE:
	case WAIT_OBJ_READ:
		break;

	case WRITE_GHOST:
		kddm_change_obj_state(set, obj_entry, objid, WRITE_OWNER);
		/* Fall through */

	case WAIT_ACK_WRITE:
	case READ_COPY:
	case READ_OWNER:
	case WRITE_OWNER:
		object = obj_entry->object;
		break;

	default:
		STATE_MACHINE_ERROR(set->id, objid, obj_entry);
		break;
	}

	if (object)
		set_object_frozen(obj_entry);

	put_kddm_obj_entry(set, obj_entry, objid);

	return object;
}
EXPORT_SYMBOL(_kddm_find_object);



void *kddm_find_object (struct kddm_ns *ns, kddm_set_id_t set_id,
			objid_t objid)
{
	struct kddm_set *set;
	void *obj;

	set = _find_get_kddm_set (ns, set_id);
	obj = _kddm_find_object (set, objid);
	put_kddm_set(set);

	return obj;
}
EXPORT_SYMBOL(kddm_find_object);
