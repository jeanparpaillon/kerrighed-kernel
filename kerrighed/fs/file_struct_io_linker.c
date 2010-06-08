/** DVFS level 3 - File Struct Linker.
 *  @file file_struct_io_linker.c
 *
 *  Copyright (C) 2006-2007, Renaud Lottiaux, Kerlabs.
 */

#include <linux/list.h>
#include <net/krgrpc/rpc.h>
#include <kddm/kddm.h>
#include <kerrighed/file.h>
#include "file_struct_io_linker.h"

struct kmem_cache *dvfs_file_cachep;

/*****************************************************************************/
/*                                                                           */
/*                     FILE_STRUCT CONTAINER IO FUNCTIONS                    */
/*                                                                           */
/*****************************************************************************/

int file_alloc_object (struct kddm_obj * obj_entry,
		       struct kddm_set * ctnr,
		       objid_t objid)
{
	struct dvfs_file_struct *dvfs_file;

	dvfs_file = kmem_cache_alloc (dvfs_file_cachep, GFP_KERNEL);
	if (dvfs_file == NULL)
		return -ENOMEM;

	dvfs_file->file = NULL;
	INIT_LIST_HEAD(&dvfs_file->list);
	obj_entry->object = dvfs_file;

	return 0;
}

int file_first_touch (struct kddm_obj * obj_entry,
		      struct kddm_set * ctnr,
		      objid_t objid,
		      int flags)
{
	return file_alloc_object(obj_entry, ctnr, objid);
}

/** Handle a container object remove.
 *  @author Renaud Lottiaux
 *
 *  @param  obj_entry  Descriptor of the object to remove.
 *  @param  ctnr      Container descriptor.
 *  @param  objid     Id of the object to remove.
 */
int file_remove_object (void *object,
			struct kddm_set * ctnr,
			objid_t objid)
{
	struct dvfs_file_struct *dvfs_file;

	dvfs_file = object;

	if (dvfs_file != NULL) {
		BUG_ON(dvfs_file->file != NULL);
		kmem_cache_free (dvfs_file_cachep, dvfs_file);
	}

	return 0;
}

/** Export an file object
 *  @author Renaud Lottiaux
 *
 *  @param  buffer    Buffer to export object data in.
 *  @param  obj_entry  Object entry of the object to export.
 */
int file_export_object (struct rpc_desc *desc,
			struct kddm_set *set,
			struct kddm_obj *obj_entry,
			objid_t objid,
			int flags)
{
	struct dvfs_file_struct *dvfs_file;

	dvfs_file = obj_entry->object;
	rpc_pack(desc, 0, dvfs_file, sizeof(struct dvfs_file_struct));

	return 0;
}

/** Import an file object
 *  @author Renaud Lottiaux
 *
 *  @param  obj_entry  Object entry of the object to import.
 *  @param  _buffer   Data to import in the object.
 */
int file_import_object (struct rpc_desc *desc,
			struct kddm_set *set,
			struct kddm_obj *obj_entry,
			objid_t objid,
			int flags)
{
	struct dvfs_file_struct *dvfs_file, buffer;

	dvfs_file = obj_entry->object;
	rpc_unpack(desc, 0, &buffer, sizeof(struct dvfs_file_struct));

	dvfs_file->f_pos = buffer.f_pos;
	dvfs_file->count = buffer.count;

	return 0;
}

/****************************************************************************/
/* Init the file_struct IO linker */

struct iolinker_struct dvfs_file_struct_io_linker = {
	alloc_object:	file_alloc_object,
	first_touch:	file_first_touch,
	export_object:	file_export_object,
	import_object:	file_import_object,
	remove_object:	file_remove_object,
	linker_name:	"DVFS ",
	linker_id:	DVFS_FILE_STRUCT_LINKER,
};
