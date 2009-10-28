/** All the code for sharing sys V shared memory segments accross the cluster
 *  @file shm_handler.c
 *
 *  Copyright (C) 2001-2006, INRIA, Universite de Rennes 1, EDF.
 *  Copyright (C) 2006-2007, Renaud Lottiaux, Kerlabs.
 */

#ifndef NO_SHM

#include <linux/ipc.h>
#include <linux/ipc_namespace.h>
#include <linux/shm.h>
#include <linux/msg.h>
#include <kddm/kddm.h>
#include <kerrighed/hotplug.h>
#include "krgshm.h"
#include "ipc_handler.h"
#include "shm_handler.h"
#include "shmid_io_linker.h"
#include "ipcmap_io_linker.h"
#include "shm_memory_linker.h"

/*****************************************************************************/
/*                                                                           */
/*                                KERNEL HOOKS                               */
/*                                                                           */
/*****************************************************************************/

static struct kern_ipc_perm *kcb_ipc_shm_lock(struct ipc_ids *ids, int id)
{
	shmid_object_t *shp_object;
	struct shmid_kernel *shp;
	int index;

	rcu_read_lock();

	index = ipcid_to_idx(id);

	shp_object = _kddm_grab_object_no_ft(ids->krgops->data_kddm_set, index);

	if (!shp_object)
		goto error;

	shp = shp_object->local_shp;

	BUG_ON(!shp);

	mutex_lock(&shp->shm_perm.mutex);

	if (shp->shm_perm.deleted) {
		mutex_unlock(&shp->shm_perm.mutex);
		goto error;
	}

	return &(shp->shm_perm);

error:
	_kddm_put_object(ids->krgops->data_kddm_set, index);
	rcu_read_unlock();

	return ERR_PTR(-EINVAL);
}

static void kcb_ipc_shm_unlock(struct kern_ipc_perm *ipcp)
{
	int index, deleted = 0;

	index = ipcid_to_idx(ipcp->id);

	if (ipcp->deleted)
		deleted = 1;

	_kddm_put_object(ipcp->krgops->data_kddm_set, index);

	if (!deleted)
		mutex_unlock(&ipcp->mutex);

	rcu_read_unlock();
}

static struct kern_ipc_perm *kcb_ipc_shm_findkey(struct ipc_ids *ids, key_t key)
{
	long *key_index;
	int id = -1;

	key_index = _kddm_get_object_no_ft(ids->krgops->key_kddm_set, key);

	if (key_index)
		id = *key_index;

	_kddm_put_object(ids->krgops->key_kddm_set, key);

	if (id != -1)
		return kcb_ipc_shm_lock(ids, id);

	return NULL;
}

/** Notify the creation of a new shm segment to Kerrighed.
 *
 *  @author Renaud Lottiaux
 */
int krg_ipc_shm_newseg (struct ipc_namespace *ns, struct shmid_kernel *shp)
{
	shmid_object_t *shp_object;
	struct kddm_set *kddm;
	long *key_index;
	int index, err;

	BUG_ON(!shm_ids(ns).krgops);

	index = ipcid_to_idx(shp->shm_perm.id);

	shp_object = _kddm_grab_object_manual_ft(
		shm_ids(ns).krgops->data_kddm_set, index);

	BUG_ON(shp_object);

	shp_object = kmem_cache_alloc(shmid_object_cachep, GFP_KERNEL);
	if (!shp_object) {
		err = -ENOMEM;
		goto err_put;
	}

	/* Create a KDDM set to host segment pages */
	kddm = _create_new_kddm_set (kddm_def_ns, 0, SHM_MEMORY_LINKER,
				     kerrighed_node_id, PAGE_SIZE,
				     &shp->shm_perm.id, sizeof(int), 0);

	if (IS_ERR(kddm)) {
		err = PTR_ERR(kddm);
		goto err_put;
	}

	shp->shm_file->f_dentry->d_inode->i_mapping->kddm_set = kddm;
	shp->shm_file->f_op = &krg_shm_file_operations;

	shp_object->set_id = kddm->id;

	shp_object->local_shp = shp;

	_kddm_set_object(shm_ids(ns).krgops->data_kddm_set, index, shp_object);

	if (shp->shm_perm.key != IPC_PRIVATE)
	{
		key_index = _kddm_grab_object(shm_ids(ns).krgops->key_kddm_set,
					      shp->shm_perm.key);
		*key_index = index;
		_kddm_put_object (shm_ids(ns).krgops->key_kddm_set,
				  shp->shm_perm.key);
	}

	shp->shm_perm.krgops = shm_ids(ns).krgops;

err_put:
	_kddm_put_object(shm_ids(ns).krgops->data_kddm_set, index);

	return 0;

}

void krg_ipc_shm_rmkey(struct ipc_namespace *ns, key_t key)
{
	_kddm_remove_object(shm_ids(ns).krgops->key_kddm_set, key);
}

void krg_ipc_shm_destroy(struct ipc_namespace *ns, struct shmid_kernel *shp)
{
	struct kddm_set *mm_set;
	int index;
	key_t key;

	index = ipcid_to_idx(shp->shm_perm.id);
	key = shp->shm_perm.key;

	mm_set = shp->shm_file->f_dentry->d_inode->i_mapping->kddm_set;

	if (key != IPC_PRIVATE) {
		_kddm_grab_object_no_ft(shm_ids(ns).krgops->key_kddm_set, key);
		_kddm_remove_frozen_object(shm_ids(ns).krgops->key_kddm_set, key);
	}

	local_shm_unlock(shp);

	_kddm_remove_frozen_object(shm_ids(ns).krgops->data_kddm_set, index);
	_destroy_kddm_set(mm_set);

	krg_ipc_rmid(&shm_ids(ns), index);
}

/*****************************************************************************/
/*                                                                           */
/*                              INITIALIZATION                               */
/*                                                                           */
/*****************************************************************************/

int krg_shm_init_ns(struct ipc_namespace *ns)
{
	int r;

	struct krgipc_ops *shm_ops = kmalloc(sizeof(struct krgipc_ops),
					     GFP_KERNEL);
	if (!shm_ops) {
		r = -ENOMEM;
		goto err;
	}

	shm_ops->map_kddm_set = create_new_kddm_set(kddm_def_ns,
						    SHMMAP_KDDM_ID,
						    IPCMAP_LINKER,
						    KDDM_RR_DEF_OWNER,
						    sizeof(ipcmap_object_t),
						    KDDM_LOCAL_EXCLUSIVE);
	if (IS_ERR(shm_ops->map_kddm_set)) {
		r = PTR_ERR(shm_ops->map_kddm_set);
		goto err_map;
	}

	shm_ops->key_kddm_set = create_new_kddm_set(kddm_def_ns,
						    SHMKEY_KDDM_ID,
						    SHMKEY_LINKER,
						    KDDM_RR_DEF_OWNER,
						    sizeof(long),
						    KDDM_LOCAL_EXCLUSIVE);
	if (IS_ERR(shm_ops->key_kddm_set)) {
		r = PTR_ERR(shm_ops->key_kddm_set);
		goto err_key;
	}

	shm_ops->data_kddm_set = create_new_kddm_set(kddm_def_ns,
						     SHMID_KDDM_ID,
						     SHMID_LINKER,
						     KDDM_RR_DEF_OWNER,
						     sizeof(shmid_object_t),
						     KDDM_LOCAL_EXCLUSIVE);
	if (IS_ERR(shm_ops->data_kddm_set)) {
		r = PTR_ERR(shm_ops->data_kddm_set);
		goto err_data;
	}

	shm_ops->ipc_lock = kcb_ipc_shm_lock;
	shm_ops->ipc_unlock = kcb_ipc_shm_unlock;
	shm_ops->ipc_findkey = kcb_ipc_shm_findkey;

	shm_ids(ns).krgops = shm_ops;

	return 0;

err_data:
	_destroy_kddm_set(shm_ops->key_kddm_set);
err_key:
	_destroy_kddm_set(shm_ops->map_kddm_set);
err_map:
	kfree(shm_ops);
err:
	return r;
}

void krg_shm_exit_ns(struct ipc_namespace *ns)
{
	if (shm_ids(ns).krgops) {

		_destroy_kddm_set(shm_ids(ns).krgops->data_kddm_set);
		_destroy_kddm_set(shm_ids(ns).krgops->key_kddm_set);
		_destroy_kddm_set(shm_ids(ns).krgops->map_kddm_set);

		kfree(shm_ids(ns).krgops);
	}
}

void shm_handler_init(void)
{
	shmid_object_cachep = kmem_cache_create("shmid_object",
						sizeof(shmid_object_t),
						0, SLAB_PANIC, NULL);

	register_io_linker(SHM_MEMORY_LINKER, &shm_memory_linker);
	register_io_linker(SHMID_LINKER, &shmid_linker);
	register_io_linker(SHMKEY_LINKER, &shmkey_linker);

	krgsyms_register(KRGSYMS_VM_OPS_SHM, &shm_vm_ops);

	printk("Shm Server configured\n");
}

void shm_handler_finalize (void)
{
}

#endif
