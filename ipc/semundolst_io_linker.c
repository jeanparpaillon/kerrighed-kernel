/*
 *  Kerrighed/modules/ipc/semundolst_io_linker.c
 *
 *  KDDM SEM undo proc list Linker.
 *
 *  Copyright (C) 2007-2008 Matthieu Fertré - INRIA
 */
#include <linux/sem.h>
#include <linux/lockdep.h>
#include <linux/security.h>
#include <linux/ipc.h>
#include <linux/ipc_namespace.h>
#include <net/krgrpc/rpc.h>
#include <kddm/kddm.h>

#include "semundolst_io_linker.h"

/*****************************************************************************/
/*                                                                           */
/*                         SEM Undo list KDDM IO FUNCTIONS                   */
/*                                                                           */
/*****************************************************************************/

static inline void __undolist_remove(struct semundo_list_object *undo_list)
{
	struct semundo_id *id, *next;

	if (undo_list) {
		for (id = undo_list->list; id; id = next) {
			next = id->next;
			kfree(id);
		}
		undo_list->list = NULL;
	}
}

static inline struct semundo_list_object * __undolist_alloc(void)
{
	struct semundo_list_object *undo_list;

	undo_list = kzalloc(sizeof(struct semundo_list_object), GFP_KERNEL);
	if (!undo_list)
		return ERR_PTR(-ENOMEM);

	return undo_list;
}

/** Handle a kddm set sem_undo_list alloc
 *  @author Matthieu Fertré
 *
 *  @param  obj_entry  Kddm object descriptor.
 *  @param  set       Kddm set descriptor
 *  @param  objid     Id of the object to create.
 */
int undolist_alloc_object (struct kddm_obj * obj_entry,
			   struct kddm_set * set,
			   objid_t objid)
{
	struct semundo_list_object *undo_list;

	undo_list = __undolist_alloc();
	if (IS_ERR(undo_list))
		return PTR_ERR(undo_list);

	obj_entry->object = undo_list;
	return 0;
}


/** Handle a kddm set sem_undo_list first touch
 *  @author Matthieu Fertré
 *
 *  @param  obj_entry  Kddm object descriptor.
 *  @param  set       Kddm set descriptor
 *  @param  objid     Id of the object to create.
 *
 *  @return  0 if everything is ok. Negative value otherwise.
 */
int undolist_first_touch (struct kddm_obj * obj_entry,
			  struct kddm_set * set,
			  objid_t objid,
			  int flags)
{
	BUG();
	return -EINVAL;
}

/** Handle a kddm sem_undo_list remove.
 *  @author Matthieu Fertré
 *
 *  @param  obj_entry  Descriptor of the object to remove.
 *  @param  set       Kddm set descriptor.
 *  @param  padeid    Id of the object to remove.
 */
int undolist_remove_object (void *object,
			    struct kddm_set * set,
			    objid_t objid)
{
	struct semundo_list_object *undo_list;
	undo_list = object;

	__undolist_remove(undo_list);
	kfree(undo_list);
	object = NULL;

	return 0;
}

/** Invalidate a kddm sem_undo_list
 *  @author Matthieu Fertré
 *
 *  @param  obj_entry  Descriptor of the object to invalidate.
 *  @param  set       Kddm set descriptor
 *  @param  objid     Id of the object to invalidate
 */
int undolist_invalidate_object (struct kddm_obj * obj_entry,
				struct kddm_set * set,
				objid_t objid)
{
	struct semundo_list_object *undo_list;
	undo_list = obj_entry->object;

	__undolist_remove(undo_list);
	obj_entry->object = NULL;

	return 0;
}

/** Export a sem_undo_list
 *  @author Matthieu Fertré
 *
 *  @param  buffer    Buffer to export object data in.
 *  @param  object    The object to export data from.
 */
int undolist_export_object (struct rpc_desc *desc,
			    struct kddm_set *set,
			    struct kddm_obj *obj_entry,
			    objid_t objid,
			    int flags)
{
	struct semundo_list_object *undo_list;
	struct semundo_id *un;
	int nb_semundo = 0, r;

	undo_list = obj_entry->object;

	r = rpc_pack_type(desc, *undo_list);
	if (r)
		goto error;

	/* counting number of semundo to send */
	for (un = undo_list->list; un;  un = un->next)
		nb_semundo++;

	r = rpc_pack_type(desc, nb_semundo);

	BUG_ON(nb_semundo != atomic_read(&undo_list->semcnt));

	/* really sending the semundo identifier */
	for (un = undo_list->list; un;  un = un->next) {
		r = rpc_pack_type(desc, *un);
		if (r)
			goto error;
	}
error:
	return r;
}

/** Import a sem_undo_list
 *  @author Matthieu Fertré
 *
 *  @param  object    The object to import data in.
 *  @param  buffer    Data to import in the object.
 */
int undolist_import_object (struct rpc_desc *desc,
			    struct kddm_set *set,
			    struct kddm_obj *obj_entry,
			    objid_t objid,
			    int flags)
{
	struct semundo_list_object *undo_list;
	struct semundo_id *un, *prev = NULL;
	int nb_semundo = 0, i=0, r;

	undo_list = obj_entry->object;

	r = rpc_unpack_type(desc, *undo_list);
	if (r)
		goto error;

	r = rpc_unpack_type(desc, nb_semundo);
	if (r)
		goto error;

	BUG_ON(nb_semundo != atomic_read(&undo_list->semcnt));

	for (i=0; i < nb_semundo; i++) {
		un = kmalloc(sizeof(struct semundo_id), GFP_KERNEL);
		if (!un) {
			r = -ENOMEM;
			goto error;
		}

		r = rpc_unpack_type(desc, *un);
		if (r)
			goto error;

		un->next = NULL;
		if (prev)
			prev->next = un;
		else
			undo_list->list = un;
		prev = un;
	}
error:
	return r;
}

/****************************************************************************/

/* Init the sem_undo_list IO linker */
struct iolinker_struct semundo_linker = {
	first_touch:       undolist_first_touch,
	remove_object:     undolist_remove_object,
	invalidate_object: undolist_invalidate_object,
	linker_name:       "semundo",
	linker_id:         SEMUNDO_LINKER,
	alloc_object:      undolist_alloc_object,
	export_object:     undolist_export_object,
	import_object:     undolist_import_object
};
