/** Global management of faf files.
 *  @file faf_file_mgr.c
 *
 *  Copyright (C) 2001-2006, INRIA, Universite de Rennes 1, EDF.
 *  Copyright (C) 2006-2007, Renaud Lottiaux, Kerlabs.
 */
#include <linux/file.h>
#include <linux/wait.h>
#include <kddm/kddm.h>
#include <net/krgrpc/rpc.h>
#include <kerrighed/file.h>
#include <kerrighed/physical_fs.h>
#include "../mobility.h"
#include <kerrighed/action.h>
#include <kerrighed/app_shared.h>
#include <kerrighed/app_terminal.h>

#include "faf_internal.h"
#include "faf_hooks.h"
#include <kerrighed/regular_file_mgr.h>

struct kmem_cache *faf_client_data_cachep;
extern const struct file_operations tty_fops;
extern const struct file_operations hung_up_tty_fops;

/** Create a faf file struct from a Kerrighed file descriptor.
 *  @author Renaud Lottiaux
 *
 *  @param task    Task to create the file for.
 *  @param desc    Kerrighed file descriptor.
 *
 *  @return   0 if everything ok.
 *            Negative value otherwise.
 */
struct file *create_faf_file_from_krg_desc (struct task_struct *task,
                                            void *_desc)
{
	faf_client_data_t *desc = _desc, *data;
	struct file *file = NULL;

	data = kmem_cache_alloc (faf_client_data_cachep, GFP_KERNEL);
	if (!data)
		return NULL;

	file = get_empty_filp ();

	if (!file) {
		kmem_cache_free (faf_client_data_cachep, data);
		goto exit;
	}

	*data = *desc;
	init_waitqueue_head(&data->poll_wq);

	file->f_dentry = NULL;
	file->f_op = &faf_file_ops;
	file->f_flags = desc->flags | O_FAF_CLT;
	file->f_mode = desc->mode;
	file->f_pos = desc->pos;
	file->private_data = data;

exit:
	return file;
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
int get_ckp_faf_file_krg_desc (int index,
			       struct file *file,
			       void **desc,
			       int *desc_size)
{
	char * tmp = (char*)__get_free_page(GFP_KERNEL), *file_name;
	regular_file_krg_desc_t *data;
	int name_len, size, r = -ENOENT;

	file_name = faf_d_path(file, tmp, PAGE_SIZE);
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

	data->file.flags = file->f_flags & (~(O_FAF_SRV | O_FAF_CLT));
	data->file.mode = file->f_mode;
	data->file.pos = file->f_pos;
	data->file.ctnrid = KDDM_SET_UNUSED;

	*desc = data;
	*desc_size = size;

	r = 0;
exit:
	free_page((unsigned long)tmp);
	return r ;
}

static void __fill_faf_file_krg_desc(faf_client_data_t *data,
				     struct file *file)
{
	unsigned int flags = file->f_flags & (~O_FAF_SRV);

	if (file->f_op == &tty_fops
	    || file->f_op == &hung_up_tty_fops)
		flags |= O_FAF_TTY;

	/* socket and fifo file can not be checkpointed */
	else if (S_ISSOCK(file->f_dentry->d_inode->i_mode)
		 || S_ISFIFO(file->f_dentry->d_inode->i_mode))
		flags |= O_KRG_NO_CHKPT;

	data->flags = flags;
	data->mode = file->f_mode;
	data->pos = file->f_pos;
	data->server_id = kerrighed_node_id;
	data->server_fd = file->f_faf_srv_index;
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
int get_faf_file_krg_desc (struct file *file,
                           void **desc,
                           int *desc_size)
{
	faf_client_data_t *data, *ldata;

	data = kmalloc(sizeof(faf_client_data_t), GFP_KERNEL);
	if (data == NULL)
		return -ENOMEM;

	/* The file descriptor is already a FAF client desc */

	if (file->f_flags & O_FAF_CLT) {
		ldata = file->private_data;
		*data = *ldata;
		goto done;
	}

	BUG_ON (!(file->f_flags & O_FAF_SRV));

	__fill_faf_file_krg_desc(data, file);

done:
	*desc = data;
	*desc_size = sizeof (faf_client_data_t);

	return 0;
}

struct cr_faf_link {
	int replaced_by_tty;
	unsigned long dvfs_objid;
	faf_client_data_t desc;
};

int cr_link_to_faf_file(struct epm_action *action, ghost_t *ghost,
			struct task_struct *task, struct file **returned_file,
			long key)
{
	int r = 0;
	struct cr_faf_link *faf_link;
	struct dvfs_file_struct *dvfs_file = NULL;
	struct file *file = NULL;
	int first_import = 0;

	BUG_ON(action->type != EPM_CHECKPOINT);

	faf_link = (struct cr_faf_link *)get_imported_shared_object(
		&action->restart.app->shared_objects,
		FAF_FILE, key);

	if (!faf_link) {
		BUG();
		r = -E_CR_BADDATA;
		goto exit;
	}

	if (faf_link->replaced_by_tty) {
		BUG();
		r = -E_CR_BADDATA;
		goto exit;
	}

	/* Check if the file struct is already present */
	file = begin_import_dvfs_file(faf_link->dvfs_objid, &dvfs_file);

	/* reopen the file if needed */
	if (!file) {
		file = create_faf_file_from_krg_desc(task, &faf_link->desc);
		first_import = 1;
	}

	r = end_import_dvfs_file(faf_link->dvfs_objid, dvfs_file, file,
				 first_import);

	if (r)
		goto exit;

	*returned_file = file;
exit:
	return r;
}

/*****************************************************************************/
/*                                                                           */
/*                            FAF FILES IMPORT/EXPORT                        */
/*                                                                           */
/*****************************************************************************/

/** Export a faf file descriptor into the given ghost.
 *  @author Renaud Lottiaux
 *
 *  @param ghost    The ghost to write data to.
 *  @param tsk      Task we are exporting.
 *  @parem index    Index of the exported file in the open files array.
 *  @param file     The file to export.
 *
 *  @return   0 if everything ok.
 *            Negative value otherwise.
 */
int faf_file_export (struct epm_action *action,
		     ghost_t *ghost,
		     struct task_struct *task,
		     int index,
		     struct file *file)
{
	void *desc;
	int desc_size;
	int r = 0;

	if (!(file->f_flags & (O_FAF_CLT | O_FAF_SRV)))
		setup_faf_file(file);

	if (action->type == EPM_CHECKPOINT) {
		BUG_ON(action->checkpoint.shared == CR_SAVE_LATER);
		r = get_ckp_faf_file_krg_desc(index, file, &desc, &desc_size);
	} else
		r = get_faf_file_krg_desc(file, &desc, &desc_size);

	if (r)
		goto error;

	r = ghost_write_file_krg_desc(ghost, desc, desc_size);
	kfree(desc);

error:
	return r;
}

/** Import a faf file descriptor from the given ghost.
 *  @author Renaud Lottiaux
 *
 *  @param ghost          The ghost to read data from.
 *  @param task           The task data are imported for.
 *  @param returned_file  The file struct where data should be imported to.
 *
 *  @return   0 if everything ok.
 *            Negative value otherwise.
 */
int faf_file_import (struct epm_action *action,
		     ghost_t *ghost,
		     struct task_struct *task,
		     struct file **returned_file)
{
	void *desc;
	struct file *file;
	int r;

	BUG_ON(action->type == EPM_CHECKPOINT);

	r = ghost_read_file_krg_desc(ghost, &desc);
	if (r)
		goto exit;

	file = create_faf_file_from_krg_desc (task, desc);

	if (IS_ERR(file)) {
		r = PTR_ERR(file);
		goto exit_free_desc;
	}
	*returned_file = file;

exit_free_desc:
	kfree(desc);
exit:
	return r;
}

struct dvfs_mobility_operations dvfs_mobility_faf_ops = {
	.file_export = faf_file_export,
	.file_import = faf_file_import,
};

static int cr_export_now_faf_file(struct epm_action *action,
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

	r = faf_file_export(action, ghost, task,
			    args->file_args.index,
			    args->file_args.file);

error:
	return r;
}

static int cr_import_now_faf_file(struct epm_action *action,
				  ghost_t *ghost,
				  struct task_struct *fake,
				  void **returned_data)
{
	int r, tty;
	void *desc;
	struct file *file;
	struct cr_faf_link *faf_link = *returned_data;

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

	memset(faf_link, 0, sizeof(struct cr_faf_link));

	/* the file will be replaced by the current terminal,
	 * no need to import
	 */
	if (tty && action->restart.app->restart.terminal) {
		faf_link->replaced_by_tty = 1;
		goto err_free_desc;
	}

	file = import_regular_file_from_krg_desc(fake, desc);

	if (IS_ERR(file)) {
		r = PTR_ERR(file);
		goto err_free_desc;
	}

	r = create_kddm_file_object(file);
	if (r)
		goto err_free_desc;

	r = setup_faf_file(file);
	if (r)
		goto err_free_desc;

	faf_link->dvfs_objid = file->f_objid;
	__fill_faf_file_krg_desc(&(faf_link->desc), file);

err_free_desc:
	kfree(desc);
error:
	return r;
}

int cr_import_complete_faf_file(struct task_struct *fake,
				void *_faf_link)
{
	struct cr_faf_link *faf_link = _faf_link;
	struct dvfs_file_struct *dvfs_file = NULL;
	struct file *file = NULL;

	if (faf_link->replaced_by_tty)
		/* the file has not been imported */
		return 0;

	dvfs_file = grab_dvfs_file_struct(faf_link->dvfs_objid);
	file = dvfs_file->file;
	if (file)
		fput(file);

	put_dvfs_file_struct(faf_link->dvfs_objid);

	return 0;
}

int cr_delete_faf_file(struct task_struct *fake, void *_faf_link)
{
	return cr_import_complete_faf_file(fake, _faf_link);
}

struct shared_object_operations cr_shared_faf_file_ops = {
        .restart_data_size = sizeof(struct cr_faf_link),
        .export_now        = cr_export_now_faf_file,
	.import_now        = cr_import_now_faf_file,
	.import_complete   = cr_import_complete_faf_file,
	.delete            = cr_delete_faf_file,
};
