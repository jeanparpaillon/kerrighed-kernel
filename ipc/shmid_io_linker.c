/** KDDM SHM id Linker.
 *  @file shmid_io_linker.c
 *
 *  Copyright (C) 2006-2007, Renaud Lottiaux, Kerlabs.
 */
#include <linux/sched.h>
#include <linux/shm.h>
#include <linux/lockdep.h>
#include <linux/security.h>
#include <linux/ipc_namespace.h>
#include <linux/ipc.h>
#include <net/krgrpc/rpc.h>
#include <kddm/kddm.h>
#include "krgshm.h"
#include "util.h"
#include "shmid_io_linker.h"
#include "shm_memory_linker.h"

#define shm_flags	shm_perm.mode
struct kmem_cache *shmid_object_cachep;



/** Create a local instance of an remotly existing SHM segment.
 *
 *  @author Renaud Lottiaux
 */
struct shmid_kernel *create_local_shp (struct shmid_kernel *received_shp,
				       kddm_set_id_t set_id)
{
	struct ipc_namespace *ns = &init_ipc_ns;
	struct shmid_kernel *shp;
	struct kddm_set *set;
	char name[13];
	int retval;

	shp = ipc_rcu_alloc(sizeof(*shp));
	if (!shp)
		return ERR_PTR(-ENOMEM);

	*shp = *received_shp;
	shp->shm_perm.security = NULL;
	retval = security_shm_alloc(shp);
	if (retval)
		goto err_putref;

	/*
	 * ipc_reserveid() locks shp
	 */
	retval = local_ipc_reserveid(&shm_ids(ns), &shp->shm_perm,
				     ns->shm_ctlmni);
	if (retval)
		goto err_security_free;

	sprintf (name, "SYSV%08x", received_shp->shm_perm.key);
	shp->shm_file = shmem_file_setup(name, shp->shm_segsz, shp->shm_flags);

	if (IS_ERR(shp->shm_file)) {
		retval = PTR_ERR(shp->shm_file);
		goto err_security_free;
	}

	set = _find_get_kddm_set(kddm_def_ns, set_id);
	BUG_ON(!set);

	shp->shm_file->f_dentry->d_inode->i_ino = shp->shm_perm.id;
	shp->shm_file->f_dentry->d_inode->i_mapping->kddm_set = set;
	shp->shm_file->f_op = &krg_shm_file_operations;
	shp->mlock_user = NULL;

	put_kddm_set(set);

	ns->shm_tot += (shp->shm_segsz + PAGE_SIZE -1) >> PAGE_SHIFT;

	shp->shm_perm.krgops = &krg_sysvipc_shm_ops;

	local_shm_unlock(shp);

	return shp;

err_security_free:
	security_shm_free(shp);
err_putref:
	ipc_rcu_putref(shp);
	return ERR_PTR(retval);
}



/*****************************************************************************/
/*                                                                           */
/*                         SHMID KDDM IO FUNCTIONS                           */
/*                                                                           */
/*****************************************************************************/



int shmid_alloc_object (struct kddm_obj * obj_entry,
			struct kddm_set * set,
			objid_t objid)
{
	shmid_object_t *shp_object;

	shp_object = kmem_cache_alloc (shmid_object_cachep, GFP_KERNEL);
	if (!shp_object)
		return -ENOMEM;

	shp_object->local_shp = NULL;
	obj_entry->object = shp_object;

	return 0;
}



/** Handle a kddm set shmid first touch
 *  @author Renaud Lottiaux
 *
 *  @param  obj_entry  Kddm object descriptor.
 *  @param  set       Kddm set descriptor
 *  @param  objid     Id of the object to create.
 *
 *  @return  0 if everything is ok. Negative value otherwise.
 */
int shmid_first_touch (struct kddm_obj * obj_entry,
		       struct kddm_set * set,
		       objid_t objid,
		       int flags)
{
	BUG(); // I should never get here !

	return -EINVAL;
}



/** Insert a new shmid in local structures.
 *  @author Renaud Lottiaux
 *
 *  @param  obj_entry  Descriptor of the object to insert.
 *  @param  set       Kddm set descriptor
 *  @param  objid     Id of the object to insert.
 */
int shmid_insert_object (struct kddm_obj * obj_entry,
			 struct kddm_set * set,
			 objid_t objid)
{
	shmid_object_t *shp_object;
	struct shmid_kernel *shp;

	shp_object = obj_entry->object;
	BUG_ON(!shp_object);

	/* Regular case, the kernel shm struct is already allocated */
	if (shp_object->local_shp)
		goto done;

	/* This is the first time the object is inserted locally. We need
	 * to allocate kernel shm structures.
	 */
	shp = create_local_shp(&shp_object->mobile_shp, shp_object->set_id);
	shp_object->local_shp = shp;

done:
	return 0;
}



/** Invalidate a kddm object shmid.
 *  @author Renaud Lottiaux
 *
 *  @param  obj_entry  Descriptor of the object to invalidate.
 *  @param  set       Kddm set descriptor
 *  @param  objid     Id of the object to invalidate
 */
int shmid_invalidate_object (struct kddm_obj * obj_entry,
			     struct kddm_set * set,
			     objid_t objid)
{
	return KDDM_IO_KEEP_OBJECT;
}



/** Handle a kddm memory page remove.
 *  @author Renaud Lottiaux
 *
 *  @param  obj_entry  Descriptor of the object to remove.
 *  @param  set       Kddm set descriptor.
 *  @param  padeid    Id of the object to remove.
 */
int shmid_remove_object (void *object,
			 struct kddm_set * set,
			 objid_t objid)
{
	shmid_object_t *shp_object;
	struct shmid_kernel *shp;

	shp_object = object;

	if (shp_object) {
		shp = shp_object->local_shp;
		local_shm_lock(&init_ipc_ns, shp->shm_perm.id);
		local_shm_destroy(&init_ipc_ns, shp);
		kmem_cache_free(shmid_object_cachep, shp_object);
	}

	return 0;
}



/** Export an object
 *  @author Renaud Lottiaux
 *
 *  @param  buffer    Buffer to export object data in.
 *  @param  object    The object to export data from.
 */
int shmid_export_object (struct rpc_desc *desc,
			 struct kddm_obj *obj_entry)
{
	shmid_object_t *shp_object;

	shp_object = obj_entry->object;
	shp_object->mobile_shp = *shp_object->local_shp;

	rpc_pack(desc, 0, shp_object, sizeof(shmid_object_t));
	return 0;
}



/** Import an object
 *  @author Renaud Lottiaux
 *
 *  @param  object    The object to import data in.
 *  @param  buffer    Data to import in the object.
 */
int shmid_import_object (struct kddm_obj *obj_entry,
			 struct rpc_desc *desc)
{
	shmid_object_t *shp_object, buffer;
	struct shmid_kernel *shp;

	shp_object = obj_entry->object;
	rpc_unpack(desc, 0, &buffer, sizeof(shmid_object_t));

	shp_object->mobile_shp = buffer.mobile_shp;
	shp_object->set_id = buffer.set_id;

	if (shp_object->local_shp) {
		shp = shp_object->local_shp;
		shp->shm_nattch = shp_object->mobile_shp.shm_nattch;
		shp->shm_perm.mode = shp_object->mobile_shp.shm_perm.mode;
	}

	return 0;
}



/****************************************************************************/

/* Init the shm id IO linker */

struct iolinker_struct shmid_linker = {
	first_touch:       shmid_first_touch,
	remove_object:     shmid_remove_object,
	invalidate_object: shmid_invalidate_object,
	insert_object:     shmid_insert_object,
	linker_name:       "shmid",
	linker_id:         SHMID_LINKER,
	alloc_object:      shmid_alloc_object,
	export_object:     shmid_export_object,
	import_object:     shmid_import_object
};



/*****************************************************************************/
/*                                                                           */
/*                         SHMKEY KDDM IO FUNCTIONS                          */
/*                                                                           */
/*****************************************************************************/



/****************************************************************************/

/* Init the shm key IO linker */

struct iolinker_struct shmkey_linker = {
	linker_name:       "shmkey",
	linker_id:         SHMKEY_LINKER,
};
