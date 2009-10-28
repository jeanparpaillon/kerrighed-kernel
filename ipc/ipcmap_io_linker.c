/** KDDM IPC allocation bitmap Linker.
 *  @file ipcmap_io_linker.c
 *
 *  Copyright (C) 2006-2007, Renaud Lottiaux, Kerlabs.
 */

#define MODULE_NAME "IPC map linker  "
#include <kddm/kddm.h>
#include "ipcmap_io_linker.h"

struct kmem_cache *ipcmap_object_cachep;

/*****************************************************************************/
/*                                                                           */
/*                           SHMID KDDM IO FUNCTIONS                         */
/*                                                                           */
/*****************************************************************************/

int ipcmap_alloc_object (struct kddm_obj * obj_entry,
			 struct kddm_set * set,
			 objid_t objid)
{
	obj_entry->object = kmem_cache_alloc(ipcmap_object_cachep, GFP_KERNEL);
	if (obj_entry->object == NULL)
		return -ENOMEM;
	return 0;
}

int ipcmap_remove_object (void *object,
			  struct kddm_set * set,
			  objid_t objid)
{
	kmem_cache_free (ipcmap_object_cachep, object);
	return 0;
}

/** First touch a kddm ipcmap object.
 *  @author Renaud Lottiaux
 *
 *  @param  obj_entr  Descriptor of the object to invalidate.
 *  @param  set       KDDM descriptor
 *  @param  objid     Id of the object to invalidate
 */
int ipcmap_first_touch_object (struct kddm_obj * obj_entry,
			       struct kddm_set * set,
			       objid_t objid,
			       int flags)
{
	ipcmap_object_t *info;

	info = kmem_cache_alloc(ipcmap_object_cachep, GFP_KERNEL);
	if (!info)
		return -ENOMEM;

	info->alloc_map = 0;

	obj_entry->object = info;
	return 0;
}

/** Invalidate a KDDM ipcmap object.
 *  @author Renaud Lottiaux
 *
 *  @param  obj_entry  Descriptor of the object to invalidate.
 *  @param  set        KDDM descriptor
 *  @param  objid      Id of the object to invalidate
 */
int ipcmap_invalidate_object (struct kddm_obj * obj_entry,
			      struct kddm_set * set,
			      objid_t objid)
{
	kmem_cache_free (ipcmap_object_cachep, obj_entry->object);
	return 0;
}

/****************************************************************************/

/* Init the shm info IO linker */

struct iolinker_struct ipcmap_linker = {
	first_touch:       ipcmap_first_touch_object,
	alloc_object:      ipcmap_alloc_object,
	remove_object:     ipcmap_remove_object,
	invalidate_object: ipcmap_invalidate_object,
	linker_name:       "ipcmap",
	linker_id:         IPCMAP_LINKER,
};
