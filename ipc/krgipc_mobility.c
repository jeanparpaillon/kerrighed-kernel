/*
 *  Kerrighed/modules/ipc/mobility.c
 *
 *  Copyright (C) 2007 Louis Rilling - Kerlabs
 *  Copyright (C) 2007-2008 Matthieu Fertré - INRIA
 */

#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <linux/ima.h>
#include <linux/ipc.h>
#include <linux/ipc_namespace.h>
#include <linux/file.h>
#include <linux/msg.h>
#include <linux/sem.h>
#include <linux/shm.h>
#include <linux/unique_id.h>
#include <kddm/kddm.h>
#include <kerrighed/ghost.h>
#include <kerrighed/ghost_helpers.h>
#include <kerrighed/action.h>
#include <kerrighed/application.h>
#include <kerrighed/app_shared.h>
#include <kerrighed/regular_file_mgr.h>
#include "krgshm.h"
#include "sem_handler.h"
#include "semundolst_io_linker.h"

extern struct kddm_set *sem_undo_list_kddm_set;

/** Return a kerrighed descriptor corresponding to the given file.
 *  @author Renaud Lottiaux
 *
 *  @param file       The file to get a Kerrighed descriptor for.
 *  @param desc       The returned descriptor.
 *  @param desc_size  Size of the returned descriptor.
 *
 *  @return   0 if everything ok.
 *            Negative value otherwise.
 */
int get_shm_file_krg_desc (struct file *file,
			   void **desc,
			   int *desc_size)
{
	regular_file_krg_desc_t *data;
	int size, r = -ENOENT;

	size = sizeof (regular_file_krg_desc_t);

	data = kmalloc (size, GFP_KERNEL);
	if (!data) {
		r = -ENOMEM;
		goto exit;
	}

	data->sysv = 1;
	data->shm.shmid = file->f_dentry->d_inode->i_ino;
	data->shm.f_mode = file->f_mode;
	*desc = data;
	*desc_size = size;

	r = 0;
exit:
	return r;
}

struct file *reopen_shm_file_entry_from_krg_desc(struct task_struct *task,
						 void *_desc)
{
	int shmid;
	int err = 0;
	struct shmid_kernel *shp;
	struct shm_file_data *sfd;
	struct file *file = NULL;
	regular_file_krg_desc_t *desc = _desc;
	struct ipc_namespace *ns;
	struct path path;

	BUG_ON (!task);
	BUG_ON (!desc);

	ns = &init_ipc_ns;

	shmid = desc->shm.shmid;

	down_read(&shm_ids(ns).rw_mutex);
	shp = shm_lock_check(&init_ipc_ns, shmid);
	if (IS_ERR(shp)) {
		err = PTR_ERR(shp);
		up_read(&shm_ids(ns).rw_mutex);
		goto out;
	}

	path.dentry = dget(shp->shm_file->f_path.dentry);
	path.mnt    = shp->shm_file->f_path.mnt;
	shm_unlock(shp);
	up_read(&shm_ids(ns).rw_mutex);

	sfd = kzalloc(sizeof(*sfd), GFP_KERNEL);
	if (!sfd) {
		err = -ENOMEM;
		goto out_put_dentry;
	}

	file = alloc_file(path.mnt, path.dentry, desc->shm.f_mode,
			  &shm_file_operations);
	if (!file) {
		err = -ENOMEM;
		goto out_free;
	}
	ima_shm_check(file);

	file->private_data = sfd;
	file->f_mapping = shp->shm_file->f_mapping;

	sfd->id = shp->shm_perm.id;
	sfd->ns = get_ipc_ns(ns);
	sfd->file = shp->shm_file;
	sfd->file->private_data = sfd;
	sfd->vm_ops = &krg_shmem_vm_ops;
out:
	if (err)
		file = ERR_PTR(err);

	return file;

out_free:
	kfree(sfd);
out_put_dentry:
	dput(path.dentry);

	down_write(&shm_ids(ns).rw_mutex);
	shp = shm_lock(ns, shmid);
	BUG_ON(IS_ERR(shp));
	shp->shm_nattch--;
	if (shp->shm_nattch == 0 &&
	    shp->shm_perm.mode & SHM_DEST)
		shm_destroy(ns, shp);
	else
		shm_unlock(shp);
	up_write(&shm_ids(ns).rw_mutex);

	goto out;
}

int export_ipc_namespace(struct epm_action *action,
			 ghost_t *ghost, struct task_struct *task)
{
	/* IPC namespace sharing is not implemented yet */
	BUG_ON (task->nsproxy->ipc_ns != &init_ipc_ns);

	return 0;
}

int import_ipc_namespace(struct epm_action *action,
			 ghost_t *ghost, struct task_struct *task)
{
	task->nsproxy->ipc_ns = get_ipc_ns(&init_ipc_ns);

	return 0;
}

void unimport_ipc_namespace(struct task_struct *task)
{
	put_ipc_ns(task->nsproxy->ipc_ns);
}


static int cr_export_later_sysv_sem(struct epm_action *action,
				    ghost_t *ghost,
				    struct task_struct *task)
{
	int r;
	long key;

	BUG_ON(action->type != EPM_CHECKPOINT);
	BUG_ON(action->checkpoint.shared != CR_SAVE_LATER);

	/* if this is not true anymore, it's time to change
	   this implementation ... */
	BUG_ON(sizeof(unique_id_t) != sizeof(long));

	key = (long)(task->sysvsem.undo_list_id);

	r = ghost_write(ghost, &key, sizeof(long));
	if (r)
		goto err;

	if (task->sysvsem.undo_list_id != UNIQUE_ID_NONE) {
		r = add_to_shared_objects_list(task->application, SEMUNDO_LIST,
					       key, 0 /* !is_local */, task,
					       NULL);

		if (r == -ENOKEY) /* the semundo list was already in the list */
			r = 0;
	}
err:
	return r;
}

int export_sysv_sem(struct epm_action *action,
		    ghost_t *ghost, struct task_struct *task)
{
	int r;
	unique_id_t undo_list_id = UNIQUE_ID_NONE;

	BUG_ON(task->sysvsem.undo_list);

	if (action->type == EPM_CHECKPOINT &&
	    action->checkpoint.shared == CR_SAVE_LATER) {
		r = cr_export_later_sysv_sem(action, ghost, task);
		return r;
	}

	/* lazy creation of semundo list:
	   - nothing to do on migration
	   - nothing to do on remote fork if CLONE_SYSVSEM is not set
	   - need to create it if CLONE_SYSVSEM and still not created */
	if (task->sysvsem.undo_list_id == UNIQUE_ID_NONE
	    && action->type == EPM_REMOTE_CLONE
	    && (action->remote_clone.clone_flags & CLONE_SYSVSEM)) {
		r = create_semundo_proc_list(task);
		if (r)
			goto err;

		undo_list_id = UNIQUE_ID_NONE;
	}

	/* does the remote process will use our undo_list ? */
	if (action->type == EPM_MIGRATE
	    || action->type == EPM_CHECKPOINT
	    || (action->type == EPM_REMOTE_CLONE
		&& (action->remote_clone.clone_flags & CLONE_SYSVSEM)))
		undo_list_id = task->sysvsem.undo_list_id;

	r = ghost_write(ghost, &undo_list_id, sizeof(unique_id_t));

err:
	return r;
}

static int cr_link_to_sysv_sem(struct epm_action *action,
			       ghost_t *ghost,
			       struct task_struct *task)
{
	int r;
	long key;
	unique_id_t undo_list_id;

	r = ghost_read(ghost, &key, sizeof(long));
	if (r)
		goto err;

	if ((unique_id_t)key == UNIQUE_ID_NONE) {
		task->sysvsem.undo_list_id = UNIQUE_ID_NONE;
	} else {
		undo_list_id = (unique_id_t)get_imported_shared_object(
			action->restart.app,
			SEMUNDO_LIST, key);

		BUG_ON(undo_list_id == UNIQUE_ID_NONE);
		r = share_existing_semundo_proc_list(task, undo_list_id);
	}
err:
	return r;
}

int import_sysv_sem(struct epm_action *action,
		    ghost_t *ghost, struct task_struct *task)
{
	int r;
	unique_id_t undo_list_id;

	task->sysvsem.undo_list = NULL; /* fake task_struct ... */

	if (action->type == EPM_CHECKPOINT
	    && action->restart.shared == CR_LINK_ONLY) {
		r = cr_link_to_sysv_sem(action, ghost, task);
		return r;
	}

	task->sysvsem.undo_list_id = UNIQUE_ID_NONE;
	/*BUG_ON(task->sysvsem.undo_list);*/

	r = ghost_read(ghost, &undo_list_id, sizeof(unique_id_t));
	if (r)
		goto err;

	if (undo_list_id != UNIQUE_ID_NONE) {
		if (action->type == EPM_CHECKPOINT)
			r = create_semundo_proc_list(task);
		else
			r = share_existing_semundo_proc_list(task,
							     undo_list_id);
	}

err:
	return r;
}

void unimport_sysv_sem(struct task_struct *task)
{
	task->sysvsem.undo_list_id = UNIQUE_ID_NONE;
}

static int cr_export_now_sysv_sem(struct epm_action *action, ghost_t *ghost,
				  struct task_struct *task,
				  union export_args *args)
{
	int r;
	r = export_sysv_sem(action, ghost, task);
	return r;
}


static int cr_import_now_sysv_sem(struct epm_action *action, ghost_t *ghost,
				  struct task_struct *fake, int local_only,
				  void ** returned_data)
{
	int r;
	BUG_ON(*returned_data != NULL);

	r = import_sysv_sem(action, ghost, fake);
	if (r)
		goto err;

	*returned_data = (void*)fake->sysvsem.undo_list_id;
err:
	return r;
}

static int cr_import_complete_sysv_sem(struct task_struct * fake,
				       void * _undo_list_id)
{
	unique_id_t undo_list_id = (unique_id_t)_undo_list_id;
	if (undo_list_id != UNIQUE_ID_NONE)
		leave_semundo_proc_list(undo_list_id);

	return 0;
}

static int cr_delete_sysv_sem(struct task_struct * fake, void * _undo_list_id)
{
	unique_id_t undo_list_id = (unique_id_t)_undo_list_id;
	semundo_list_object_t * undo_list;

	undo_list = _kddm_grab_object_no_ft(sem_undo_list_kddm_set,
					    undo_list_id);
	if (undo_list)
		_kddm_remove_frozen_object(sem_undo_list_kddm_set,
					   undo_list_id);
	else
		_kddm_put_object(sem_undo_list_kddm_set,
				 undo_list_id);

	return 0;
}


struct shared_object_operations cr_shared_semundo_ops = {
        .restart_data_size = 0,
        .export_now        = cr_export_now_sysv_sem,
	.import_now        = cr_import_now_sysv_sem,
	.import_complete   = cr_import_complete_sysv_sem,
	.delete            = cr_delete_sysv_sem,
};
