/** MM Struct Linker.
 *  @file mm_struct_io_linker.c
 *
 *  Copyright (C) 2008-2009, Renaud Lottiaux, Kerlabs.
 */
#include <linux/rmap.h>
#include <net/krgrpc/rpc.h>
#include <kddm/kddm.h>

#include "mm_struct.h"
#include "vma_struct.h"



/*****************************************************************************/
/*                                                                           */
/*                       MM_STRUCT KDDM SET IO FUNCTIONS                     */
/*                                                                           */
/*****************************************************************************/



int mm_alloc_object (struct kddm_obj *obj_entry,
		     struct kddm_set *set,
		     objid_t objid)
{
	obj_entry->object = NULL;
	return 0;
}



int mm_first_touch (struct kddm_obj *obj_entry,
		    struct kddm_set *set,
		    objid_t objid,
		    int flags)
{
	/* Should never be called */
	BUG();

	return 0;
}



int mm_remove_object (void *object,
		      struct kddm_set *set,
		      objid_t objid)
{
	struct mm_struct *mm = object;

	/* Take the mmap_sem to avoid race condition with clean_up_mm_struct */

	atomic_inc(&mm->mm_count);
	down_write(&mm->mmap_sem);

	mmput(mm);

	up_write(&mm->mmap_sem);

	mm->mm_id = 0;

	mmdrop(mm);

	return 0;
}



/** Export an MM struct
 *  @author Renaud Lottiaux
 *
 *  @param  buffer    Buffer to export object data in.
 *  @param  obj_entry  Object entry of the object to export.
 */
int mm_export_object (struct rpc_desc *desc,
		      struct kddm_obj *obj_entry)
{
	struct mm_struct *mm;
	krgsyms_val_t unmap_id, get_unmap_id;

	mm = obj_entry->object;

	krgnode_set (desc->client, mm->copyset);

	rpc_pack(desc, 0, &mm->mm_id, sizeof(unique_id_t));
	rpc_pack(desc, 0, &mm->anon_vma_kddm_id, sizeof(unique_id_t));
	rpc_pack(desc, 0, &mm->context.vdso, sizeof(void*));

	get_unmap_id = krgsyms_export(mm->get_unmapped_area);
	BUG_ON(mm->get_unmapped_area && get_unmap_id == KRGSYMS_UNDEF);
	rpc_pack_type(desc, get_unmap_id);

	unmap_id = krgsyms_export(mm->unmap_area);
	BUG_ON(mm->unmap_area && unmap_id == KRGSYMS_UNDEF);
	rpc_pack_type(desc, unmap_id);

	return 0;
}



/** Import an MM struct
 *  @author Renaud Lottiaux
 *
 *  @param  obj_entry  Object entry of the object to import.
 *  @param  _buffer   Data to import in the object.
 */
int mm_import_object (struct kddm_obj *obj_entry,
		      struct rpc_desc *desc)
{
	struct mm_struct *mm;
	krgsyms_val_t unmap_id, get_unmap_id;
	struct kddm_set *set;
	unique_id_t mm_id, kddm_id;
	void *context_vdso;
	int r;

	mm = obj_entry->object;

	r = rpc_unpack (desc, 0, &mm_id, sizeof(unique_id_t));
	if (r)
		return r;

	r = rpc_unpack (desc, 0, &kddm_id, sizeof(unique_id_t));
	if (r)
		return r;

	r = rpc_unpack (desc, 0, &context_vdso, sizeof(void*));
	if (r)
		return r;

	if (mm == NULL) {
		/* First import */
		set = _find_get_kddm_set(kddm_def_ns, kddm_id);
		BUG_ON (set == NULL);

		mm = set->obj_set;
		mm->mm_id = mm_id;
		atomic_inc(&mm->mm_users);
		obj_entry->object = mm;
		put_kddm_set(set);
		mm->context.vdso = context_vdso;
	}

	r = rpc_unpack_type(desc, get_unmap_id);
	if (r)
		return r;

	mm->get_unmapped_area = krgsyms_import (get_unmap_id);

	r = rpc_unpack_type(desc, unmap_id);
	if (r)
		return r;
	mm->unmap_area = krgsyms_import (unmap_id);

	return 0;
}



/****************************************************************************/

/* Init the mm_struct IO linker */

struct iolinker_struct mm_struct_io_linker = {
	alloc_object:      mm_alloc_object,
	first_touch:       mm_first_touch,
	export_object:     mm_export_object,
	import_object:     mm_import_object,
	remove_object:     mm_remove_object,
	linker_name:       "MM ",
	linker_id:         MM_STRUCT_LINKER,
};
