/** KDDM set object
 *  @file kddm_set_object.c
 *
 *  Implementation of KDDM set object function.
 *
 *  Copyright (C) 2006-2007, Renaud Lottiaux, Kerlabs.
 */
#include <linux/module.h>

#include <kddm/kddm.h>
#include <kddm/object_server.h>
#include "protocol_action.h"


/** Set the initial value of an object.
 *  @author Renaud Lottiaux
 *
 *  @param set        KDDM set hosting the object.
 *  @param obj_entry  Object entry of the object to set.
 *  @param objid      Identifier of the object to set.
 *  @param object     Object to store in the kddm set entry.
 *
 *  This function assumes that a call to kddm_*_object_manual_ft has been done
 *  before. A kddm_put_object must be done after.
 *
 *  @return        0 if everything OK, -1 otherwise.
 */
int _kddm_set_object_state(struct kddm_set *set,
			    objid_t objid,
			    void *object,
			    kddm_obj_state_t state)
{
	struct kddm_obj *obj_entry;

retry:
	obj_entry = __get_kddm_obj_entry(set, objid);

	BUG_ON(OBJ_STATE(obj_entry) != INV_OWNER);
	BUG_ON(!object_frozen(obj_entry));

	if (obj_entry->object != NULL) {
		kddm_io_remove_object_and_unlock(obj_entry, set, objid, NULL);
		printk ("Humf.... Can do really better !\n");
		goto retry;
	}

	obj_entry->object = object;
	atomic_inc(&set->nr_objects);
	ADD_TO_SET (COPYSET(obj_entry), kerrighed_node_id);
	kddm_insert_object (set, objid, obj_entry, state);
	put_kddm_obj_entry(set, obj_entry, objid);

	return 0;
}



int kddm_set_object_state(struct kddm_ns *ns, kddm_set_id_t set_id,
			  objid_t objid, void *object, kddm_obj_state_t state)
{
	struct kddm_set *set;
	int res;

	set = _find_get_kddm_set (ns, set_id);
	res = _kddm_set_object_state(set, objid, object, state);
	put_kddm_set(set);

	return res;
}



int _kddm_set_object(struct kddm_set *set, objid_t objid, void *object)
{
	return _kddm_set_object_state(set, objid, object, WRITE_OWNER);
}
EXPORT_SYMBOL(_kddm_set_object);

int kddm_set_object(struct kddm_ns *ns, kddm_set_id_t set_id, objid_t objid,
		     void *object)
{
	struct kddm_set *set;
	int res;

	set = _find_get_kddm_set (ns, set_id);
	res = _kddm_set_object_state(set, objid, object, WRITE_OWNER);
	put_kddm_set(set);

	return res;
}
EXPORT_SYMBOL(kddm_set_object);
