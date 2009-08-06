/** Global management of regular files.
 *  @file regular_file_mgr.c
 *
 *  Copyright (C) 2001-2006, INRIA, Universite de Rennes 1, EDF.
 *  Copyright (C) 2006-2007, Renaud Lottiaux, Kerlabs.
 */
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/file.h>
#ifdef CONFIG_KRG_IPC
#include <linux/ipc.h>
#include <linux/shm.h>
#include <linux/msg.h>
#include <linux/ipc_namespace.h>
#endif
#include <kddm/kddm.h>
#include <kerrighed/action.h>
#include <kerrighed/app_shared.h>
#include <kerrighed/app_terminal.h>
#include <kerrighed/file.h>
#include <kerrighed/ghost_helpers.h>
#include <kerrighed/regular_file_mgr.h>
#include <kerrighed/physical_fs.h>
#include "mobility.h"

/*****************************************************************************/
/*                                                                           */
/*                             REGULAR FILES CREATION                        */
/*                                                                           */
/*****************************************************************************/

struct file *reopen_file_entry_from_krg_desc (struct task_struct *task,
                                              regular_file_krg_desc_t *desc)
{
	struct file *file = NULL;

	BUG_ON (!task);
	BUG_ON (!desc);

	file = open_physical_file (desc->file.filename, desc->file.flags,
				   desc->file.mode, desc->file.uid,
				   desc->file.gid);

	if (IS_ERR (file))
		return file;

	file->f_pos = desc->file.pos;

	return file;
}

struct file *create_file_entry_from_krg_desc (struct task_struct *task,
                                              regular_file_krg_desc_t *desc)
{
	struct file *file = NULL;

	BUG_ON (!task);
	BUG_ON (!desc);

	file = open_physical_file(desc->file.filename, desc->file.flags,
				  desc->file.mode,
				  task->cred->fsuid, task->cred->fsgid);

	if (IS_ERR (file))
		return file;

	file->f_pos = desc->file.pos;
	file->f_dentry->d_inode->i_mode |= desc->file.mode;

	return file;
}

/** Create a regular file struct from a Kerrighed file descriptor.
 *  @author Renaud Lottiaux, Matthieu Fertré
 *
 *  @param task    Task to create the file for.
 *  @param desc    Kerrighed file descriptor.
 *
 *  @return   0 if everything ok.
 *            Negative value otherwise.
 */
struct file *import_regular_file_from_krg_desc (struct task_struct *task,
                                                void *_desc)
{
	regular_file_krg_desc_t *desc = _desc;

	BUG_ON (!task);
	BUG_ON (!desc);

	desc->file.filename = (char *) &desc[1];

#ifdef CONFIG_KRG_IPC
	if (desc->sysv)
		return reopen_shm_file_entry_from_krg_desc (task, desc);
#endif

	if (desc->file.ctnrid != KDDM_SET_UNUSED)
		return create_file_entry_from_krg_desc (task, desc);
	else
		return reopen_file_entry_from_krg_desc (task, desc);
}

int check_flush_file (struct epm_action *action,
		      fl_owner_t id,
		      struct file *file)
{
	int err = 0;

	switch (action->type) {
	case EPM_REMOTE_CLONE:
	case EPM_MIGRATE:
	case EPM_CHECKPOINT:
		  if (file->f_dentry) {
			  if (file->f_op && file->f_op->flush)
				  err = file->f_op->flush(file, id);
		  }

		  break;

	  default:
		  break;
	}

	return err;
}

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
int get_regular_file_krg_desc (struct file *file,
                               void **desc,
                               int *desc_size)
{
	char *tmp = (char *) __get_free_page (GFP_KERNEL), *file_name;
	regular_file_krg_desc_t *data;
	int size = 0, name_len;
	int r = -ENOENT;

#ifdef CONFIG_KRG_IPC
	BUG_ON(file->f_op == &krg_shm_file_operations);

	if (file->f_op == &shm_file_operations) {
		r = get_shm_file_krg_desc(file, desc, desc_size);
		goto exit;
	}
#endif

	file_name = physical_d_path(&file->f_path, tmp);

	if (!file_name)
		goto exit;

	name_len = strlen (file_name) + 1;
	size = sizeof (regular_file_krg_desc_t) + name_len;

	data = kmalloc (size, GFP_KERNEL);
	if (!data) {
		r = -ENOMEM;
		goto exit;
	}

	data->sysv = 0;
	data->file.filename = (char *) &data[1];

	strncpy(data->file.filename, file_name, name_len);

	data->file.flags = file->f_flags;
	data->file.mode = file->f_dentry->d_inode->i_mode & S_IRWXUGO;
	data->file.pos = file->f_pos;
	data->file.uid = file->f_cred->uid;
	data->file.gid = file->f_cred->gid;
	if (file->f_dentry->d_inode->i_mapping->kddm_set)
		data->file.ctnrid = file->f_dentry->d_inode->i_mapping->kddm_set->id;
	else
		data->file.ctnrid = KDDM_SET_UNUSED;

	*desc = data;
	*desc_size = size;

	r = 0;

exit:
	free_page ((unsigned long) tmp);

	return r;
}

/*****************************************************************************/

int ghost_read_file_krg_desc(ghost_t *ghost, void **desc)
{
       int r;
       int desc_size;

       r = ghost_read(ghost, &desc_size, sizeof (int));
       if (r)
               goto error;

       *desc = kmalloc(desc_size, GFP_KERNEL);
       if (!(*desc)) {
                 r = -ENOMEM;
                goto error;
       }

       r = ghost_read(ghost, *desc, desc_size);
       if (r) {
               kfree(*desc);
               *desc = NULL;
       }
error:
       return r;
}

int ghost_write_file_krg_desc(ghost_t *ghost, void *desc, int desc_size)
{
	int r;

	r = ghost_write (ghost, &desc_size, sizeof (int));
	if (r)
		goto error;

	r = ghost_write (ghost, desc, desc_size);
error:
	return r;
}

int ghost_write_regular_file_krg_desc(ghost_t *ghost, struct file *file)
{
	int r;
	void *desc;
	int desc_size;

	r = get_regular_file_krg_desc(file, &desc, &desc_size);
	if (r)
		goto error;

	r = ghost_write_file_krg_desc(ghost, desc, desc_size);
	kfree (desc);
error:
	return r;
}

/*****************************************************************************/

struct cr_regular_file_link {
	int replaced_by_tty;
	struct file *file;
};

int cr_link_to_local_regular_file(struct epm_action *action, ghost_t *ghost,
				  struct task_struct *task,
				  struct file **returned_file,
				  long key)
{
	int r = 0;
	struct cr_regular_file_link *file_link;

	/* look in the table to find the new allocated data
	 imported in import_shared_objects */

	file_link = get_imported_shared_object(action->restart.app,
					       REGULAR_FILE, key);

	if (!file_link) {
		BUG();
		r = -E_CR_BADDATA;
		goto exit;
	}

	if (file_link->replaced_by_tty) {
		BUG();
		r = -E_CR_BADDATA;
		goto exit;
	}

	*returned_file = file_link->file;

	get_file(*returned_file);

exit:
	return r;
}

struct file *begin_import_dvfs_file(unsigned long dvfs_objid,
				    struct dvfs_file_struct **dvfs_file)
{
       struct file *file = NULL;

       /* Check if the file struct is already present */
       *dvfs_file = grab_dvfs_file_struct(dvfs_objid);
       file = (*dvfs_file)->file;
       if (file)
               get_file(file);

       return file;
}

int end_import_dvfs_file(unsigned long dvfs_objid,
			 struct dvfs_file_struct *dvfs_file,
			 struct file *file, int first_import)
{
       int r = 0;

       if (IS_ERR(file)) {
               r = PTR_ERR (file);
               goto error;
       }

       if (first_import) {
	       /* This is the first time the file is imported on this node
		* Setup the DVFS file field and inc the DVFS counter.
		*/
               file->f_objid = dvfs_objid;
               dvfs_file->file = file;

               dvfs_file->count++;
       }

error:
       put_dvfs_file_struct(dvfs_objid);
       return r;
}

struct cr_dvfs_file_link {
	int replaced_by_tty;
	unsigned long dvfs_objid;
};

int cr_link_to_dvfs_regular_file(struct epm_action *action,
				 ghost_t *ghost,
				 struct task_struct *task,
				 void *desc,
				 struct file **returned_file,
				 long key)
{
	int r = 0;
	struct cr_dvfs_file_link *file_link;
	struct dvfs_file_struct *dvfs_file = NULL;
	struct file *file = NULL;
	int first_import = 0;

	/* look in the table to find the new allocated data
	 imported in import_shared_objects */

	file_link = get_imported_shared_object(action->restart.app,
					       REGULAR_DVFS_FILE, key);

	if (!file_link) {
		BUG();
		r = -E_CR_BADDATA;
		goto exit;
	}

	if (file_link->replaced_by_tty) {
		BUG();
		r = -E_CR_BADDATA;
		goto exit;
	}

	/* Check if the file struct is already present */
	file = begin_import_dvfs_file(file_link->dvfs_objid, &dvfs_file);

	/* reopen the file if needed */
	if (!file) {
		file = import_regular_file_from_krg_desc(task, desc);
		first_import = 1;
	}

	r = end_import_dvfs_file(file_link->dvfs_objid, dvfs_file, file,
				 first_import);

	if (r)
		goto exit;

	check_flush_file(action, task->files, file);
	*returned_file = file;

	BUG_ON(file->f_objid != file_link->dvfs_objid);

exit:
	return r;
}

/*****************************************************************************/
/*                                                                           */
/*                          REGULAR FILES IMPORT/EXPORT                      */
/*                                                                           */
/*****************************************************************************/

/** Export a regular file descriptor into the given ghost.
 *  @author Renaud Lottiaux
 *
 *  @param ghost      the ghost to write data to.
 *  @param file       The file to export.
 *
 *  @return   0 if everything ok.
 *            Negative value otherwise.
 */
int regular_file_export (struct epm_action *action,
			 ghost_t *ghost,
                         struct task_struct *task,
                         int index,
                         struct file *file)
{
	int r = 0;

	BUG_ON(action->type == EPM_CHECKPOINT
	       && action->checkpoint.shared == CR_SAVE_LATER);

	check_flush_file(action, task->files, file);

	r = ghost_write_regular_file_krg_desc(ghost, file);

	return r;
}

int __regular_file_import_from_desc(struct epm_action *action,
				    void *desc,
				    struct task_struct *task,
				    struct file **returned_file)
{
	int r = 0;
	struct file *file;

	file = import_regular_file_from_krg_desc(task, desc);
	if (IS_ERR(file)) {
		r = PTR_ERR (file);
		goto exit;
	}

	check_flush_file(action, task->files, file);
	*returned_file = file;

exit:
	return r;
}

/** Import a regular file descriptor from the given ghost.
 *  @author Renaud Lottiaux
 *
 *  @param ghost          The ghost to read data from.
 *  @param task           The task data are imported for.
 *  @param returned_file  The file struct where data should be imported to.
 *
 *  @return   0 if everything ok.
 *            Negative value otherwise.
 */
int regular_file_import (struct epm_action *action,
			 ghost_t *ghost,
                         struct task_struct *task,
                         struct file **returned_file)
{
	void *desc;
	int r = 0;

	BUG_ON(action->type == EPM_CHECKPOINT);

	r = ghost_read_file_krg_desc(ghost, &desc);
	if (r)
		goto exit;

	r = __regular_file_import_from_desc(action, desc, task, returned_file);

	kfree (desc);
exit:
	return r;
}



struct dvfs_mobility_operations dvfs_mobility_regular_ops = {
	.file_export = regular_file_export,
	.file_import = regular_file_import,
};

static int cr_export_now_regular_file(struct epm_action *action,
				      ghost_t *ghost,
				      struct task_struct *task,
				      union export_args *args)
{
	int r, tty;

	tty = is_tty(args->file_args.file);
	if (tty < 0) {
		r = tty;
		goto error;
	}

	r = ghost_write(ghost, &tty, sizeof(int));
	if (r)
		goto error;

	r = regular_file_export(action, ghost, task,
				args->file_args.index,
				args->file_args.file);

error:
	return r;
}


static int cr_import_now_regular_file(struct epm_action *action,
				      ghost_t *ghost,
				      struct task_struct *fake,
				      int local_only,
				      void **returned_data)
{
	int r, tty;
	void *desc;
	struct file *f;
	struct cr_regular_file_link *file_link = *returned_data;

	r = ghost_read(ghost, &tty, sizeof(int));
	if (r)
		goto error;

	if (tty != 0 && tty != 1) {
		BUG();
		r = -E_CR_BADDATA;
		goto error;
	}

	/* We need to read the file description from the ghost
	 * even if we may not use it
	 */
	r = ghost_read_file_krg_desc(ghost, &desc);
	if (r)
		goto error;

	memset(file_link, 0, sizeof(struct cr_regular_file_link));

	/* the file will be replaced by the current terminal,
	 * no need to import
	 */
	if (tty && action->restart.app->restart.terminal) {
		file_link->replaced_by_tty = 1;
		goto err_free_desc;
	}

	r = __regular_file_import_from_desc(action, desc, fake, &f);
	if (r)
		goto err_free_desc;

	file_link->file = f;

err_free_desc:
	kfree(desc);

error:
	return r;
}

static int cr_import_complete_regular_file(struct task_struct *fake,
					   void *_file_link)
{
	struct cr_regular_file_link *file_link = _file_link;

	if (file_link->replaced_by_tty)
		/* the file has not been imported */
		return 0;

	BUG_ON(atomic_read(&(file_link->file->f_count)) <= 1);
	fput(file_link->file);

	return 0;
}

static int cr_delete_regular_file(struct task_struct *fake,
				  void *_file_link)
{
	struct cr_regular_file_link *file_link = _file_link;

	if (file_link->replaced_by_tty)
		/* the file has not been imported */
		return 0;

	if (file_link->file)
		fput(file_link->file);

	return 0;
}

static int cr_import_now_dvfs_file(struct epm_action *action,
				   ghost_t *ghost,
				   struct task_struct *fake,
				   int local_only,
				   void **returned_data)
{
	int r, tty;
	struct file *f;
	struct cr_dvfs_file_link *file_link = *returned_data;
	void *desc;

	r = ghost_read(ghost, &tty, sizeof(int));
	if (r)
		goto error;

	if (tty != 0 && tty != 1) {
		BUG();
		r = -E_CR_BADDATA;
		goto error;
	}

	memset(file_link, 0, sizeof(struct cr_regular_file_link));

	/* We need to read the file description from the ghost
	 * even if we may not use it
	 */
	r = ghost_read_file_krg_desc(ghost, &desc);
	if (r)
		goto error;

	/* the file will be replaced by the current terminal,
	 * no need to import
	 */
	if (tty && action->restart.app->restart.terminal) {
		file_link->replaced_by_tty = 1;
		goto error;
	}

	r = __regular_file_import_from_desc(action, desc, fake, &f);
	if (r)
		goto error;

	/* get a new dvfs objid
	 */
	r = create_kddm_file_object(f);
	if (r)
		goto error;

	file_link->dvfs_objid = f->f_objid;

error:
	return r;
}

static int cr_import_complete_dvfs_file(struct task_struct *fake,
					void *_file_link)
{
	struct cr_dvfs_file_link *file_link = _file_link;
	struct dvfs_file_struct *dvfs_file = NULL;
	struct file *file = NULL;

	if (file_link->replaced_by_tty)
		/* the file has not been imported */
		return 0;

	dvfs_file = grab_dvfs_file_struct(file_link->dvfs_objid);
	BUG_ON(!dvfs_file);

	file = dvfs_file->file;
	BUG_ON(!file);
	BUG_ON(atomic_read(&file->f_count) <= 1);

	fput(file);

	put_dvfs_file_struct(file_link->dvfs_objid);

	return 0;
}

static int cr_delete_dvfs_file(struct task_struct *fake,
				  void *_file_link)
{
	int r = 0;
	struct cr_dvfs_file_link *file_link = _file_link;
	struct dvfs_file_struct *dvfs_file = NULL;
	struct file *file = NULL;

	if (file_link->replaced_by_tty)
		/* the file has not been imported */
		return 0;

	dvfs_file = grab_dvfs_file_struct(file_link->dvfs_objid);
	if (!dvfs_file) {
		r = -ENOENT;
		goto error;
	}

	file = dvfs_file->file;
	if (file)
		fput(file);

error:
	put_dvfs_file_struct(file_link->dvfs_objid);
	return 0;
}

struct shared_object_operations cr_shared_regular_file_ops = {
        .restart_data_size = sizeof(struct cr_regular_file_link),
	.export_now        = cr_export_now_regular_file,
	.import_now        = cr_import_now_regular_file,
	.import_complete   = cr_import_complete_regular_file,
	.delete            = cr_delete_regular_file,
};

struct shared_object_operations cr_shared_dvfs_regular_file_ops = {
        .restart_data_size = sizeof(struct cr_dvfs_file_link),
        .export_now        = cr_export_now_regular_file,
	.import_now        = cr_import_now_dvfs_file,
	.import_complete   = cr_import_complete_dvfs_file,
	.delete            = cr_delete_dvfs_file,
};
