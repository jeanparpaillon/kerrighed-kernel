/** KDDM grab object
 *  @file kddm_grab_object.c
 *
 *  Implementation of KDDM grab object function.
 *
 *  Copyright (C) 2001-2006, INRIA, Universite de Rennes 1, EDF.
 *  Copyright (C) 2006-2007, Renaud Lottiaux, Kerlabs.
 */
#include <linux/module.h>

#include <kddm/kddm.h>
#include <kddm/object_server.h>
#include "protocol_action.h"

static inline struct kddm_obj *check_cow (struct kddm_set *set,
					  struct kddm_obj *obj_entry,
					  objid_t objid,
					  int flags,
					  int *retry)
{
	*retry = 0;
	if (flags & KDDM_COW_OBJECT) {
		if (object_frozen(obj_entry)) {
			if (!(flags & KDDM_ASYNC_REQ)) {
				sleep_on_kddm_obj(set, obj_entry, objid,
						  flags);
				*retry = 1;
			}
		}
		else
			obj_entry = kddm_break_cow_object(set, obj_entry,
							  objid,
							  KDDM_BREAK_COW_COPY);
	}
	return obj_entry;
}

/** Get a copy of a object and invalidate any other existing copy.
 *  @author Renaud Lottiaux
 *
 *  @param set        KDDM set hosting the object.
 *  @param obj_entry  Object entry of the object to grab.
 *  @param objid      Identifier of the object to grab.
 *  @param flags      Sync / Async request, FT or not, etc...
 *
 *  @return              Address of the object if found.
 *                       NULL if the object does not exist.
 *                       Negative value if error.
 */
void *generic_kddm_grab_object(struct kddm_set *set,
			       objid_t objid,
			       int flags)
{
	struct kddm_obj *obj_entry;
	void *object;
	int retry;

	inc_grab_object_counter(set);

	obj_entry = __get_alloc_kddm_obj_entry(set, objid);

try_again:
	switch (OBJ_STATE(obj_entry)) {
	case READ_COPY:
		if (object_frozen(obj_entry)) {
			if (flags & KDDM_ASYNC_REQ)
				BUG();
			goto sleep;
		}

	case INV_COPY:
		request_object_on_write(set, obj_entry, objid, flags);
		CLEAR_SET(COPYSET(obj_entry));
		kddm_change_obj_state(set, obj_entry, objid, WAIT_OBJ_WRITE);
		if (flags & KDDM_TRY_GRAB)
			goto sleep_on_wait_page;
		/* Else Fall through */

	case WAIT_ACK_WRITE:
	case WAIT_OBJ_WRITE:
	case INV_FILLING:
		if (flags & KDDM_TRY_GRAB)
			goto exit_try_failed;

		if (flags & KDDM_ASYNC_REQ)
			goto exit_no_freeze;

sleep_on_wait_page:
		sleep_on_kddm_obj(set, obj_entry, objid, flags);

		if (OBJ_STATE(obj_entry) == WRITE_OWNER) {
			obj_entry = check_cow (set, obj_entry, objid, flags,
					       &retry);
			if (retry)
				goto try_again;
			break;
		}

		if (flags & KDDM_NO_FT_REQ) {
			if (OBJ_STATE(obj_entry) == INV_OWNER)
				break;

			if (OBJ_STATE(obj_entry) == INV_COPY) {
				if (!(flags & KDDM_SEND_OWNERSHIP))
					break;
				BUG();
			}
		}

		if (flags & KDDM_TRY_GRAB)
			goto exit_try_failed;

		/* Argh, object has been invalidated before we woke up. */
		goto try_again;

	case INV_OWNER:
		if (flags & KDDM_NO_FT_REQ)
			break;

		/*** The object can be created on the local node  ***/
		if (object_first_touch(set, obj_entry, objid,
				       WRITE_OWNER, flags) != 0)
			BUG();
		break;

	case READ_OWNER:
		obj_entry = check_cow (set, obj_entry, objid, flags,
				       &retry);
		if (retry)
			goto try_again;

		if (!OBJ_EXCLUSIVE(obj_entry)) {
			kddm_change_obj_state(set, obj_entry, objid,
					      WAIT_ACK_WRITE);
			request_copies_invalidation(set, obj_entry, objid,
						    kerrighed_node_id);
			if (flags & KDDM_ASYNC_REQ)
				goto exit_no_freeze;
			sleep_on_kddm_obj(set, obj_entry, objid, flags);

			if (OBJ_STATE(obj_entry) != WRITE_OWNER) {
				/* Argh, object has been invalidated before
				   we woke up. */
				goto try_again;
			}
		} else
			kddm_change_obj_state(set, obj_entry, objid,
					      WRITE_OWNER);
		break;

	case WRITE_OWNER:
		obj_entry = check_cow (set, obj_entry, objid, flags, &retry);
		if (retry)
			goto try_again;
		break;

	case WRITE_GHOST:
		obj_entry = check_cow (set, obj_entry, objid, flags, &retry);
		if (retry)
			goto try_again;
		kddm_change_obj_state(set, obj_entry, objid, WRITE_OWNER);
		break;

	case WAIT_ACK_INV:
	case WAIT_OBJ_READ:
		if (flags & KDDM_TRY_GRAB)
			goto exit_try_failed;

		/* Fall through */
	case WAIT_OBJ_RM_DONE:
	case WAIT_OBJ_RM_ACK:
	case WAIT_OBJ_RM_ACK2:
	case WAIT_CHG_OWN_ACK:
sleep:
		if (flags & KDDM_ASYNC_REQ)
			goto exit_no_freeze;

		sleep_on_kddm_obj(set, obj_entry, objid, flags);
		goto try_again;

	default:
		STATE_MACHINE_ERROR(set->id, objid, obj_entry);
		break;
	}

	if (flags & KDDM_ASYNC_REQ)
		goto exit_no_freeze;

	if (object_frozen(obj_entry) &&
	    (flags & KDDM_TRY_GRAB) &&
	    (kddm_local_exclusive (set)))
		goto exit_try_failed;

	if (check_sleep_on_local_exclusive(set, obj_entry, objid, flags))
		goto try_again;

	if (!(flags & KDDM_NO_FREEZE))
		set_object_frozen(obj_entry);

exit_no_freeze:
	object = obj_entry->object;
	put_kddm_obj_entry(set, obj_entry, objid);

	return object;

exit_try_failed:
	put_kddm_obj_entry(set, obj_entry, objid);
	return ERR_PTR(-EBUSY);
}



void *_kddm_grab_object(struct kddm_set *set, objid_t objid)
{
	return generic_kddm_grab_object(set, objid, 0);
}
EXPORT_SYMBOL(_kddm_grab_object);

void *kddm_grab_object(struct kddm_ns *ns, kddm_set_id_t set_id, objid_t objid)
{
	struct kddm_set *set;
	void *obj;

	set = _find_get_kddm_set (ns, set_id);
	obj = generic_kddm_grab_object(set, objid, 0);
	put_kddm_set(set);

	return obj;
}
EXPORT_SYMBOL(kddm_grab_object);

void *fkddm_grab_object(struct kddm_ns *ns, kddm_set_id_t set_id,
			objid_t objid, int flags)
{
	struct kddm_set *set;
	void *obj;

	set = _find_get_kddm_set (ns, set_id);
	obj = generic_kddm_grab_object(set, objid, flags);
	put_kddm_set(set);

	return obj;
}
EXPORT_SYMBOL(fkddm_grab_object);



void *_async_kddm_grab_object(struct kddm_set *set, objid_t objid)
{
	return generic_kddm_grab_object(set, objid, KDDM_ASYNC_REQ);
}
EXPORT_SYMBOL(_async_kddm_grab_object);

void *async_kddm_grab_object(struct kddm_ns *ns, kddm_set_id_t set_id,
			     objid_t objid)
{
	struct kddm_set *set;
	void *obj;

	set = _find_get_kddm_set (ns, set_id);
	obj = generic_kddm_grab_object(set, objid, KDDM_ASYNC_REQ);
	put_kddm_set(set);

	return obj;
}
EXPORT_SYMBOL(async_kddm_grab_object);



void *_kddm_grab_object_no_ft(struct kddm_set *set, objid_t objid)
{
	return generic_kddm_grab_object(set, objid, KDDM_NO_FT_REQ);
}
EXPORT_SYMBOL(_kddm_grab_object_no_ft);

void *kddm_grab_object_no_ft(struct kddm_ns *ns, kddm_set_id_t set_id,
			     objid_t objid)
{
	struct kddm_set *set;
	void *obj;

	set = _find_get_kddm_set (ns, set_id);
	obj = generic_kddm_grab_object(set, objid, KDDM_NO_FT_REQ);
	put_kddm_set(set);

	return obj;
}
EXPORT_SYMBOL(kddm_grab_object_no_ft);



void *_async_kddm_grab_object_no_ft(struct kddm_set *set, objid_t objid)
{
	return generic_kddm_grab_object(set, objid, KDDM_NO_FT_REQ |
					KDDM_ASYNC_REQ);
}
EXPORT_SYMBOL(_async_kddm_grab_object_no_ft);

void *async_kddm_grab_object_no_ft(struct kddm_ns *ns, kddm_set_id_t set_id,
				   objid_t objid)
{
	struct kddm_set *set;
	void *obj;

	set = _find_get_kddm_set (ns, set_id);
	obj = generic_kddm_grab_object(set, objid, KDDM_NO_FT_REQ |
				       KDDM_ASYNC_REQ);
	put_kddm_set(set);

	return obj;
}
EXPORT_SYMBOL(async_kddm_grab_object_no_ft);



void *_kddm_grab_object_manual_ft(struct kddm_set *set, objid_t objid)
{
	return generic_kddm_grab_object(set, objid, KDDM_NO_FT_REQ |
					KDDM_SEND_OWNERSHIP);
}
EXPORT_SYMBOL(_kddm_grab_object_manual_ft);

void *kddm_grab_object_manual_ft(struct kddm_ns *ns, kddm_set_id_t set_id,
				 objid_t objid)
{
	struct kddm_set *set;
	void *obj;

	set = _find_get_kddm_set (ns, set_id);
	obj = generic_kddm_grab_object(set, objid, KDDM_NO_FT_REQ |
				       KDDM_SEND_OWNERSHIP);
	put_kddm_set(set);

	return obj;
}
EXPORT_SYMBOL(kddm_grab_object_manual_ft);



void *_kddm_grab_object_no_lock(struct kddm_set *set, objid_t objid)
{
	return generic_kddm_grab_object(set, objid, KDDM_NO_FREEZE);
}
EXPORT_SYMBOL(_kddm_grab_object_no_lock);

void *kddm_grab_object_no_lock(struct kddm_ns *ns, kddm_set_id_t set_id,
			       objid_t objid)
{
	struct kddm_set *set;
	void *obj;

	set = _find_get_kddm_set (ns, set_id);
	obj = generic_kddm_grab_object(set, objid, KDDM_NO_FREEZE);
	put_kddm_set(set);

	return obj;
}
EXPORT_SYMBOL(kddm_grab_object_no_lock);


void *_kddm_try_grab_object(struct kddm_set *set, objid_t objid)
{
	return generic_kddm_grab_object(set, objid, KDDM_TRY_GRAB);
}
EXPORT_SYMBOL(_kddm_try_grab_object);

void *_kddm_grab_object_cow(struct kddm_set *set, objid_t objid)
{
	return generic_kddm_grab_object(set, objid, KDDM_COW_OBJECT);
}
EXPORT_SYMBOL(_kddm_grab_object_cow);


void *kddm_try_grab_object(struct kddm_ns *ns, kddm_set_id_t set_id,
			   objid_t objid)
{
	struct kddm_set *set;
	void *obj;

	set = _find_get_kddm_set (ns, set_id);
	obj = generic_kddm_grab_object(set, objid, KDDM_TRY_GRAB);
	put_kddm_set(set);

	return obj;
}
EXPORT_SYMBOL(kddm_try_grab_object);
