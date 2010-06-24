/** KDDM sync object
 *  @file kddm_sync_object.c
 *
 *  Implementation of KDDM sync object function.
 *
 *  Copyright (C) 2006-2007, Renaud Lottiaux, Kerlabs.
 */
#include <linux/module.h>

#include <kddm/kddm.h>
#include <kddm/object_server.h>
#include "protocol_action.h"


/** Synchronize an object with its attached physical device.
 *  @author Renaud Lottiaux
 *
 *  @param set        KDDM set hosting the object.
 *  @param obj_entry  Object entry of the object to sync.
 *  @param objid      Identifier of the object to sync.
 *  @param dest       Identifier of the node to send object to if needed.
 *  @return           0 if everything OK, -1 otherwise.
 */
int _kddm_sync_frozen_object(struct kddm_set *set,
			     objid_t objid)
{
	kddm_obj_state_t new_state = INV_COPY;
	struct kddm_obj *obj_entry;
	int res = -1;

	BUG_ON(!kddm_ft_linked(set));

	obj_entry = __get_kddm_obj_entry(set, objid);
	if (obj_entry == NULL)
		return -ENOENT;

	BUG_ON(!object_frozen(obj_entry));

	switch (OBJ_STATE(obj_entry)) {
	case WRITE_OWNER:
		new_state = READ_OWNER;
		break;

	case READ_OWNER:
	case READ_COPY:
		new_state = OBJ_STATE(obj_entry);
		break;

	default:
		STATE_MACHINE_ERROR(set->id, objid, obj_entry);
		break;
	}

	if (I_AM_DEFAULT_OWNER(set, objid)) {
		put_kddm_obj_entry(set, obj_entry, objid);
		res = kddm_io_sync_object(obj_entry, set, objid);
	}
	else
		request_sync_object_and_unlock(set, obj_entry, objid,
					       new_state);

	return res;
}
EXPORT_SYMBOL(_kddm_sync_frozen_object);

int kddm_sync_frozen_object(struct kddm_ns *ns, kddm_set_id_t set_id,
			    objid_t objid)
{
	struct kddm_set *set;
	int res;

	set = _find_get_kddm_set (ns, set_id);
	res = _kddm_sync_frozen_object(set, objid);
	put_kddm_set(set);

	return res;
}
EXPORT_SYMBOL(kddm_sync_frozen_object);
