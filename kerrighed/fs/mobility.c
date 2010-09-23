/** Implementation of DFS mobility mechanisms.
 *  @file dfs_mobility.c
 *
 *  Copyright (C) 2001-2006, INRIA, Universite de Rennes 1, EDF.
 *  Copyright (C) 2006-2007, Renaud Lottiaux, Kerlabs.
 *
 *  Implementation of functions used to migrate, duplicate and checkpoint
 *  DFS data, process memory and file structures.
 */
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/fs_struct.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/mnt_namespace.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/rcupdate.h>

#include <kddm/kddm.h>
#include <kerrighed/namespace.h>
#include <kerrighed/ghost.h>
#include <kerrighed/ghost_helpers.h>
#include <kerrighed/action.h>
#include <kerrighed/application.h>
#include <kerrighed/app_shared.h>
#include <kerrighed/file.h>
#include <kerrighed/file_stat.h>
#include "mobility.h"
#include <kerrighed/regular_file_mgr.h>
#include <kerrighed/physical_fs.h>
#include <kerrighed/pid.h>
#include "file_struct_io_linker.h"
#ifdef CONFIG_KRG_FAF
#include <kerrighed/faf.h>
#include <kerrighed/faf_file_mgr.h>
#include "faf/faf_internal.h"
#include "faf/faf_hooks.h"
#endif

#define VM_FILE_NONE 0
#define VM_FILE_PHYS 1

#define MMAPPED_FILE -1

void free_ghost_files (struct task_struct *ghost)
{
	struct fdtable *fdt;

	BUG_ON (ghost->files == NULL);

	fdt = files_fdtable(ghost->files);

	BUG_ON (fdt->close_on_exec == NULL);
	BUG_ON (fdt->open_fds == NULL);

	exit_files(ghost);
	exit_fs(ghost);
}

/*****************************************************************************/
/*                                                                           */
/*                              HELPER FUNCTIONS                             */
/*                                                                           */
/*****************************************************************************/

static inline int populate_fs_struct (ghost_t * ghost,
				      char *buffer,
				      struct path *path)
{
	struct prev_root root;
	int len, r;

	r = ghost_read (ghost, &len, sizeof (int));
	if (r)
		goto error;

	if (len == 0) {
		path->dentry = NULL;
		path->mnt = NULL;
		return 0;
	}

	r = ghost_read(ghost, buffer, len);
	if (r)
		goto error;

	chroot_to_physical_root(&root);
	r = kern_path(buffer, LOOKUP_FOLLOW | LOOKUP_DIRECTORY, path);
	chroot_to_prev_root(&root);
	if (r)
		goto error;

error:
	return r;
}


static struct dvfs_mobility_operations *get_dvfs_mobility_ops(struct file *file)
{
#ifdef CONFIG_KRG_FAF
	if (file->f_flags & (O_FAF_SRV | O_FAF_CLT))
		return &dvfs_mobility_faf_ops;
#endif

	return &dvfs_mobility_regular_ops;
}

/*****************************************************************************/
/*                                                                           */
/*                              EXPORT FUNCTIONS                             */
/*                                                                           */
/*****************************************************************************/

/** Generic function to export an open file into a ghost.
 *  Not used by Checkpoint.
 *  @author Renaud Lottiaux
 *
 *  @param ghost    Ghost where data should be stored.
 *  @param tsk      Task we are exporting.
 *  @parem index    Index of the exported file in the open files array.
 *  @param file     Struct of the file to export.
 *
 *  @return  0 if everything ok.
 *           Negative value otherwise.
 */
int export_one_open_file (struct epm_action *action,
			  ghost_t *ghost,
                          struct task_struct *tsk,
                          int index,
                          struct file *file)
{
	struct dvfs_mobility_operations *ops;
	krgsyms_val_t dvfs_ops_type;
	int r;

	BUG_ON(action->type == EPM_CHECKPOINT);

	if (!can_export_file(file)) {
		r = -ENOSYS;
		goto err;
	}

	if (index != MMAPPED_FILE) {
		if (!file->f_objid)
			create_kddm_file_object(file);
		check_file_struct_sharing (index, file, action);
	}

#ifdef CONFIG_KRG_FAF
	r = check_activate_faf(tsk, index, file, action);
	if (r)
		goto err;
#endif
	ops = get_dvfs_mobility_ops(file);

	dvfs_ops_type = krgsyms_export(ops);

	r = ghost_write(ghost, &dvfs_ops_type, sizeof(krgsyms_val_t));
	if (r)
		goto err;

	r = ghost_write(ghost, &file->f_objid,
			sizeof (unsigned long));
	if (r)
		goto err;

	r = ops->file_export (action, ghost, tsk, index, file);

err:
	return r;
}

static int get_file_size(struct file *file, loff_t *size)
{
	int r = 0;
	struct kstat stat;

	r = do_fstat(file, &stat);
	if (r)
		goto exit;

	*size = stat.size;
exit:
	return r;
}

static int _cr_get_file_type_and_key(const struct file *file,
				     enum shared_obj_type *type,
				     long *key,
				     enum object_locality *locality,
				     int allow_unsupported)
{
	if (!can_checkpoint_file(file)
	    && !allow_unsupported)
		return -ENOSYS;

	if (file->f_objid) {
		*type = DVFS_FILE;
		*key = file->f_objid;
		if (locality) {
			if (is_anonymous_pipe(file)) {
				if (file->f_flags & O_FAF_CLT)
					*locality = SHARED_SLAVE;
				else
					*locality = SHARED_MASTER;
			} else
				*locality = SHARED_ANY;
		}
	} else {
		*type = LOCAL_FILE;
		*key = (long)file;
		if (locality)
			*locality = LOCAL_ONLY;
	}

	return 0;
}

void cr_get_file_type_and_key(const struct file *file,
			      enum shared_obj_type *type,
			      long *key,
			      int allow_unsupported)
{
	int r;
	r = _cr_get_file_type_and_key(file, type, key, NULL, allow_unsupported);

	/* normally, the error have been catched before */
	BUG_ON(r);
}

static int cr_ghost_write_file_id(ghost_t *ghost, struct file *file,
				  int allow_unsupported)
{
	int r;
	long key;
	enum shared_obj_type type;

	cr_get_file_type_and_key(file, &type, &key, allow_unsupported);

	r = ghost_write(ghost, &type, sizeof(enum shared_obj_type));
	if (r)
		goto error;

	r = ghost_write(ghost, &key, sizeof(long));
	if (r)
		goto error;

error:
	return r;
}

static int cr_write_vma_phys_file_id(ghost_t *ghost, struct vm_area_struct *vma)
{
	int r;
	int anon_shared;

	anon_shared = is_anon_shared_mmap(vma->vm_file);

	r = ghost_write_type(ghost, anon_shared);
	if (r || anon_shared)
		goto exit;

	r = cr_ghost_write_file_id(ghost, vma->vm_file, 0);
	if (r)
		goto exit;

	if (vma->vm_flags & VM_EXEC) {

		/* to check it is the same file when restarting */
		loff_t file_size;
		r = get_file_size(vma->vm_file, &file_size);
		if (r)
			goto exit;

		r = ghost_write(ghost, &file_size, sizeof(loff_t));
		if (r)
			goto exit;
	}
exit:
	return r;
}

static int export_vma_phys_file(struct epm_action *action,
				ghost_t *ghost,
				struct task_struct *tsk,
				struct vm_area_struct *vma,
				hashtable_t *file_table)
{
	struct file *file = vma->vm_file;
	unsigned long key = (unsigned long)file;
	int export_file = 1;
	int r;

	if (action->type == EPM_CHECKPOINT) {
		BUG_ON(action->checkpoint.shared != CR_SAVE_NOW);
		r = cr_write_vma_phys_file_id(ghost, vma);
		goto done;
	}

	/* Don't try to share SHM files */
	if (file->f_op == &krg_shm_file_operations)
		goto export_file;

	if (__hashtable_find(file_table, key))
		/* File already exported. Don't export it again */
		export_file = 0;
	else {
		/* First export ? Add the file in the export file table */
		r = __hashtable_add(file_table, key, file);
		if (r)
			goto done;
	}

export_file:
	r = ghost_write(ghost, &key, sizeof(unsigned long));
	if (r)
		goto done;

	r = ghost_write(ghost, &export_file, sizeof(int));
	if (r)
		goto done;

	/* Only export the file once */
	if (export_file)
		r = export_one_open_file(action, ghost, tsk,
					 MMAPPED_FILE, file);

done:
	return r;
}

/** Export the file associated to a VMA.
 *  @author Renaud Lottiaux
 *
 *  @param ghost    Ghost where data should be stored.
 *  @param vma      The VMA hosting the file to export.
 *
 *  @return  0 if everything ok.
 *           Negative value otherwise.
 */
int export_vma_file (struct epm_action *action,
		     ghost_t *ghost,
		     struct task_struct *tsk,
                     struct vm_area_struct *vma,
		     hashtable_t *file_table)
{
	int vm_file_type;
	int r;

	/* Creation of the vm_file ghost */

	if (vma->vm_file == NULL)
		vm_file_type = VM_FILE_NONE;
	else
		vm_file_type = VM_FILE_PHYS;

	r = ghost_write (ghost, &vm_file_type, sizeof (int));
	if (r)
		goto err;

	switch (vm_file_type) {
	case VM_FILE_NONE:
		break;
	case VM_FILE_PHYS:
		  r = export_vma_phys_file(action, ghost, tsk, vma,
					   file_table);
		break;
	default:
		BUG();
	}

err:
	return r;
}

int export_mm_exe_file(struct epm_action *action, ghost_t *ghost,
		       struct task_struct *tsk)
{
	int dump = 0, r = 0;

#ifdef CONFIG_PROC_FS
	if (tsk->mm->exe_file) {
		dump = 1;
		r = ghost_write(ghost, &dump, sizeof(int));
		if (r)
			goto exit;

		if (action->type == EPM_CHECKPOINT) {
			BUG_ON(action->checkpoint.shared != CR_SAVE_NOW);
			r = cr_ghost_write_file_id(ghost, tsk->mm->exe_file, 0);
		} else
			r = export_one_open_file(action, ghost, tsk, -1,
						 tsk->mm->exe_file);
	} else
		r = ghost_write(ghost, &dump, sizeof(int));

exit:
#endif
	return r;
}

/** Export the open files array of a process
 *  Not used by Checkpoint
 *  @author  Geoffroy Vallee, Renaud Lottiaux
 *
 *  @param ghost  Ghost where file data should be stored.
 *  @param tsk    Task to export file data from.
 *
 *  @return  0 if everything ok.
 *           Negative value otherwise.
 */
int export_open_files (struct epm_action *action,
		       ghost_t *ghost,
                       struct task_struct *tsk,
		       struct fdtable *fdt,
		       int last_open_fd)
{
	struct file *file;
	int i, r = 0;

	BUG_ON (!tsk);
	BUG_ON(action->type == EPM_CHECKPOINT);

	/* Export files opened by the process */
	for (i = 0; i < last_open_fd; i++) {
		if (FD_ISSET (i, fdt->open_fds)) {
			BUG_ON (!fdt->fd[i]);
			file = fdt->fd[i];

			r = export_one_open_file (action, ghost, tsk, i, file);

			if (r != 0)
				goto exit;
		} else {
			if (fdt->fd[i] != NULL)
				printk ("Entry %d : %p\n", i, fdt->fd[i]);
			BUG_ON (fdt->fd[i] != NULL);
		}
	}

exit:
	return r;
}

static int cr_write_open_files_id(ghost_t *ghost,
				  struct task_struct *tsk,
				  struct fdtable *fdt,
				  int last_open_fd)
{
	struct file *file;
	int i, allow_unsupported, r = 0;

	BUG_ON (!tsk);

	if (tsk->application->checkpoint.flags & CKPT_W_UNSUPPORTED_FILE)
		allow_unsupported = 1;
	else
		allow_unsupported = 0;

	/* Write id of files opened by the process */
	for (i = 0; i < last_open_fd; i++) {
		if (FD_ISSET (i, fdt->open_fds)) {
			BUG_ON (!fdt->fd[i]);
			file = fdt->fd[i];

			r = cr_ghost_write_file_id(ghost, file,
						   allow_unsupported);

			if (r != 0)
				goto exit;
		} else {
			if (fdt->fd[i] != NULL)
				printk ("Entry %d : %p\n", i, fdt->fd[i]);
			BUG_ON (fdt->fd[i] != NULL);
		}
	}

exit:
	return r;
}

int _cr_add_file_to_shared_table(struct task_struct *task,
				 int index, struct file *file,
				 int allow_unsupported)
{
	int r, force;
	long key;
	enum shared_obj_type type;
	enum object_locality locality;
	union export_args args;

	r = _cr_get_file_type_and_key(file, &type, &key, &locality,
				      allow_unsupported);
	if (r)
		goto error;

	args.file_args.index = index;
	args.file_args.file = file;

	if (index == -1)
		force = 0;
	else
		force = 1;

	r = add_to_shared_objects_list(task->application,
				       type, key, locality, task,
				       &args, force);

	if (r == -ENOKEY) /* the file was already in the list */
               r = 0;

error:
	return r;
}

int cr_add_file_to_shared_table(struct task_struct *task,
				int index, struct file *file,
				int allow_unsupported)
{
	int r;

	r = _cr_add_file_to_shared_table(task, index, file,
					 allow_unsupported);
	if (r)
		goto error;

	if (!(file->f_flags & O_FAF_CLT) && is_anonymous_pipe(file)) {
		r = cr_add_pipe_inode_to_shared_table(task, file);
		if (r)
			goto error;
	}

error:
	return r;
}

static int cr_add_files_to_shared_table(struct task_struct *tsk,
					struct fdtable *fdt,
					int last_open_fd)
{
	struct file *file;
	int i, allow_unsupported, r = 0;

	BUG_ON (!tsk);

	if (tsk->application->checkpoint.flags & CKPT_W_UNSUPPORTED_FILE)
		allow_unsupported = 1;
	else
		allow_unsupported = 0;

	/* Write id of files opened by the process */
	for (i = 0; i < last_open_fd; i++) {
		if (FD_ISSET (i, fdt->open_fds)) {
			BUG_ON (!fdt->fd[i]);
			file = fdt->fd[i];

			r = cr_add_file_to_shared_table(tsk, i, file,
							allow_unsupported);

			if (r != 0)
				goto exit;
		} else {
			if (fdt->fd[i] != NULL)
				printk ("Entry %d : %p\n", i, fdt->fd[i]);
			BUG_ON (fdt->fd[i] != NULL);
		}
	}

exit:
	return r;
}

static int cr_export_later_files_struct(ghost_t *ghost,
					struct task_struct *task)
{
	int r;
	long key;
	int last_open_fd;
	struct fdtable *fdt;

	key = (long)(task->files);

	r = ghost_write(ghost, &key, sizeof(long));
	if (r)
		goto err;

	r = add_to_shared_objects_list(task->application,
				       FILES_STRUCT, key, LOCAL_ONLY,
				       task, NULL, 0);
	if (r && r != -ENOKEY)
		goto err;

	/*
	 * we need to check the files to see if they are shared even if
	 * the files_struct itself is shared. These is needed to export
	 * valid information to user to help file substitution.
	 */
	rcu_read_lock();
	fdt = files_fdtable(task->files);

	last_open_fd = count_open_files(fdt);
	r = cr_add_files_to_shared_table(task, fdt, last_open_fd);
	rcu_read_unlock();

err:
	return r;
}

/** Export the files_struct of a process
 *  @author Renaud Lottiaux
 *
 *  @param ghost  Ghost where file data should be stored.
 *  @param tsk    Task to export file data from.
 *
 *  @return  0 if everything ok.
 *           Negative value otherwise.
 */
int export_files_struct (struct epm_action *action,
			 ghost_t *ghost,
                         struct task_struct *tsk)
{
	int r = 0, export_fdt;
	int last_open_fd;
	struct fdtable *fdt;
	struct files_struct *exported_files;

	BUG_ON (!tsk);

	{
		int magic = 780574;

		r = ghost_write (ghost, &magic, sizeof (int));
		if (r)
			goto err;
	}

	if (action->type == EPM_CHECKPOINT &&
	    action->checkpoint.shared == CR_SAVE_LATER) {

		r = cr_export_later_files_struct(ghost, tsk);
		return r;
	}

	/* Export the main files structure */

	exported_files = dup_fd (tsk->files, &r);
	if (!exported_files)
		goto err;

	r = ghost_write (ghost, exported_files, sizeof (struct files_struct));
	if (r)
		goto exit_put_files;

	/* Export the bit vector close_on_exec */

	fdt = files_fdtable(exported_files);

	last_open_fd = count_open_files(fdt);
	r = ghost_write (ghost, &last_open_fd, sizeof (int));
	if (r)
		goto exit_put_files;

	export_fdt = (fdt != &exported_files->fdtab);
	r = ghost_write (ghost, &export_fdt, sizeof (int));
	if (r)
		goto exit_put_files;

	if (export_fdt) {
		int nr = last_open_fd / BITS_PER_BYTE;
		r = ghost_write (ghost, fdt->close_on_exec, nr);
		if (r)
			goto exit_put_files;

		r = ghost_write (ghost, fdt->open_fds, nr);
		if (r)
			goto exit_put_files;

	}

	{
		int magic = 280574;

		r = ghost_write (ghost, &magic, sizeof (int));
		if (r)
			goto exit_put_files;
	}

	if (action->type == EPM_CHECKPOINT) {
		BUG_ON(action->checkpoint.shared != CR_SAVE_NOW);
		r = cr_write_open_files_id(ghost, tsk, fdt, last_open_fd);
	} else
		r = export_open_files (action, ghost, tsk, fdt, last_open_fd);

	if (r)
		goto exit_put_files;

	{
		int magic = 380574;

		r = ghost_write (ghost, &magic, sizeof (int));
	}

exit_put_files:
	put_files_struct (exported_files);

err:
	if (r)
		epm_error(action, r, tsk,
			  "Fail to save struct files_struct");

	return r;
}

static int cr_export_later_fs_struct(struct epm_action *action,
				     ghost_t *ghost,
				     struct task_struct *task)
{
	int r;
	long key;

	BUG_ON(action->type != EPM_CHECKPOINT);
	BUG_ON(action->checkpoint.shared != CR_SAVE_LATER);

	key = (long)(task->fs);

	r = ghost_write(ghost, &key, sizeof(long));
	if (r)
		goto err;

	r = add_to_shared_objects_list(task->application,
				       FS_STRUCT, key, LOCAL_ONLY, task,
				       NULL, 0);

	if (r == -ENOKEY) /* the fs_struct was already in the list */
		r = 0;
err:
	return r;
}

/** Export the fs_struct of a process
 *  @author Renaud Lottiaux
 *
 *  @param ghost  Ghost where file data should be stored.
 *  @param tsk    Task to export file data from.
 *
 *  @return  0 if everything ok.
 *           Negative value otherwise.
 */
int export_fs_struct (struct epm_action *action,
		      ghost_t *ghost,
                      struct task_struct *tsk)
{
	char *tmp, *file_name;
	int r, len;

	if (action->type == EPM_CHECKPOINT &&
	    action->checkpoint.shared == CR_SAVE_LATER) {
		int r;
		r = cr_export_later_fs_struct(action, ghost, tsk);
		return r;
	}

	r = -ENOMEM;
	tmp = (char *) __get_free_page (GFP_KERNEL);
	if (!tmp)
		goto err_write;

	{
		int magic = 55611;

		r = ghost_write (ghost, &magic, sizeof (int));
		if (r)
			goto err_write;
	}

	/* Export the umask value */

	r = ghost_write (ghost, &tsk->fs->umask, sizeof (int));
	if (r)
			goto err_write;

	/* Export the root path name */

	file_name = physical_d_path(&tsk->fs->root, tmp, false);
	if (!file_name) {
		r = -ENOENT;
		goto err_write;
	}

	len = strlen (file_name) + 1;
	r = ghost_write (ghost, &len, sizeof (int));
	if (r)
			goto err_write;
	r = ghost_write (ghost, file_name, len);
	if (r)
			goto err_write;

	/* Export the pwd path name */

	file_name = physical_d_path(&tsk->fs->pwd, tmp, false);
	if (!file_name) {
		r = -ENOENT;
		goto err_write;
	}

	len = strlen (file_name) + 1;
	r = ghost_write (ghost, &len, sizeof (int));
	if (r)
			goto err_write;
	r = ghost_write (ghost, file_name, len);
	if (r)
			goto err_write;

	{
		int magic = 180574;

		r = ghost_write (ghost, &magic, sizeof (int));
	}

err_write:
	free_page ((unsigned long) tmp);

	if (r)
		epm_error(action, r, tsk,
			  "Fail to save struct fs_struct");

	return r;
}

int export_mnt_namespace(struct epm_action *action,
			 ghost_t *ghost, struct task_struct *tsk)
{
	/* Nothing done right now... */
	if (tsk->nsproxy->mnt_ns != tsk->nsproxy->krg_ns->root_nsproxy.mnt_ns)
		return -EPERM;
	return 0;
}

/*****************************************************************************/
/*                                                                           */
/*                              IMPORT FUNCTIONS                             */
/*                                                                           */
/*****************************************************************************/

/** Generic function to import an open file from a ghost.
 *  Not used by Restart.
 *  @author Renaud Lottiaux
 *
 *  @param ghost   Ghost where data should be read from.
 *  @param task    the task to import the file for.
 *  @param file    The resulting imported file structure.
 *
 *  @return   0 if everything ok.
 *            Negative value otherwise.
 */
int import_one_open_file (struct epm_action *action,
			  ghost_t *ghost,
                          struct task_struct *task,
			  int index,
                          struct file **returned_file)
{
	struct dvfs_file_struct *dvfs_file = NULL;
	struct dvfs_mobility_operations *ops;
	struct file *file = NULL, *imported_file = NULL;
	krgsyms_val_t dvfs_ops_type;
	unsigned long objid;
	int first_import = 0;
	int r = 0;

	BUG_ON(action->type == EPM_RESTART);

	*returned_file = NULL;

	r = ghost_read(ghost, &dvfs_ops_type, sizeof (dvfs_ops_type));
	if (r)
		goto err_read;
	r = ghost_read(ghost, &objid, sizeof (unsigned long));
	if (r)
		goto err_read;

	ops = krgsyms_import(dvfs_ops_type);

	/* We need to import the file, to avoid leaving unused data in
	 * the ghost... We can probably do better...
	 */
	r = ops->file_import (action, ghost, task, &imported_file);
	if (r)
		goto err_read;

	if (index == MMAPPED_FILE) {
		*returned_file = imported_file;
		goto exit;
	}

	/* Check if the file struct is already present */
	file = begin_import_dvfs_file(objid, &dvfs_file);

	/* If a file struct was alreay present, use it and discard the one we
	 * have just created. If f_count == 0, someone else is being freeing
	 * the structure.
	 */
	if (file) {
		/* The file has already been imported on this node */
#ifdef CONFIG_KRG_FAF
		free_faf_file_private_data(imported_file);
#endif
		fput(imported_file);
		*returned_file = file;
	}
	else {
		*returned_file = imported_file;
		first_import = 1;
	}

	r = end_import_dvfs_file(objid, dvfs_file, *returned_file, first_import);
	if (!r)
		goto exit;

	if (first_import) {
#ifdef CONFIG_KRG_FAF
		free_faf_file_private_data(imported_file);
#endif
		fput(imported_file);
		*returned_file = NULL;
	}

exit:
err_read:
	return r;
}

/** Imports the open files of the process
 *  Not used by Restart.
 *  @author  Geoffroy Vallee, Renaud Lottiaux
 *
 *  @param ghost  Ghost where open files data are stored.
 *  @param tsk    Task to load open files data in.
 *
 *  @return  0 if everything ok.
 *           Negative value otherwise.
 */
int import_open_files (struct epm_action *action,
		       ghost_t *ghost,
                       struct task_struct *tsk,
		       struct files_struct *files,
		       struct fdtable *fdt,
		       int last_open_fd)
{
	int i, j, r = 0;

	BUG_ON(action->type == EPM_RESTART);

	/* Reception of the files list and their names */
	for (i = 0; i < last_open_fd; i++) {
		if (FD_ISSET (i, fdt->open_fds)) {
			r = import_one_open_file (action, ghost, tsk, i,
						  (void *) &fdt->fd[i]);
			if (r != 0)
				goto err;
			BUG_ON (!fdt->fd[i]);
		}
		else
			fdt->fd[i] = NULL;
	}
exit:
	return r;

err:
	for (j = 0; j < i; j++) {
		if (fdt->fd[j])
			filp_close(fdt->fd[j], files);
	}

	goto exit;
}

static int cr_link_to_open_files(struct epm_action *action,
				 ghost_t *ghost,
				 struct task_struct *tsk,
				 struct files_struct *files,
				 struct fdtable *fdt,
				 int last_open_fd)
{
	int i, r = 0;

	BUG_ON(action->type == EPM_RESTART
	       && action->restart.shared == CR_LINK_ONLY);

	/* Linking the files in the files_struct */
	for (i = 0; i < last_open_fd; i++) {
		if (FD_ISSET (i, fdt->open_fds)) {
			r = cr_link_to_file(action, ghost, tsk,
					    (void *) &fdt->fd[i]);
			if (r != 0)
				goto exit;

			/* in case of unsupported files and related option
			 * cr_link_to_file may return r==0 with
			 * fdt->fd[i] == NULL
			 */
			if (!fdt->fd[i])
				FD_CLR(i, fdt->open_fds);
		}
		else
			fdt->fd[i] = NULL;
	}

exit:
	return r;
}

static int cr_link_to_files_struct(struct epm_action *action,
				   ghost_t *ghost,
				   struct task_struct *tsk)
{
	int r;
	long key;
	struct files_struct *files;

	r = ghost_read(ghost, &key, sizeof(long));
	if (r)
		goto err;

	files = get_imported_shared_object(action->restart.app,
					   FILES_STRUCT, key);

	if (!files) {
		r = -E_CR_BADDATA;
		goto err;
	}

	/* the task is not yet hashed, no need to lock */
	atomic_inc(&files->count);
	tsk->files = files;
err:
	return r;
}

/** Imports the files informations of the process
 *  @author Renaud Lottiaux
 *
 *  @param ghost  Ghost where files data are stored.
 *  @param tsk    Task to load files data in.
 *
 *  @return  0 if everything ok.
 *           Negative value otherwise.
 */
int import_files_struct (struct epm_action *action,
			 ghost_t *ghost,
                         struct task_struct *tsk)
{
	int import_fdt;
	int last_open_fd;
	int r = -ENOMEM;
	struct files_struct *files;
	struct fdtable *fdt;

	{
		int magic = 0;

		r = ghost_read (ghost, &magic, sizeof (int));

		BUG_ON (!r && magic != 780574);
	}

	if (action->type == EPM_RESTART
	    && action->restart.shared == CR_LINK_ONLY) {
		r = cr_link_to_files_struct(action, ghost, tsk);
		return r;
	}

	/* Import the main files structure */

	files = kmem_cache_alloc (files_cachep, GFP_KERNEL);
	if (files == NULL)
		return -ENOMEM;

	r = ghost_read (ghost, files, sizeof (struct files_struct));
	if (r)
		goto exit_free_files;

	atomic_set (&files->count, 1);
	spin_lock_init (&files->file_lock);

	r = ghost_read (ghost, &last_open_fd, sizeof (int));
	if (r)
		goto exit_free_files;
	r = ghost_read (ghost, &import_fdt, sizeof (int));
	if (r)
		goto exit_free_files;

	/* Import the open files table structure */

	if (import_fdt) {
		unsigned int cpy, set;

		fdt = alloc_fdtable(last_open_fd);
		if (fdt == NULL)
			goto exit_free_files;

		cpy = last_open_fd * sizeof(struct file *);
		set = (fdt->max_fds - last_open_fd) * sizeof(struct file *);
		memset((char *)(fdt->fd) + cpy, 0, set);

		cpy = last_open_fd / BITS_PER_BYTE;
		set = (fdt->max_fds - last_open_fd) / BITS_PER_BYTE;

		r = ghost_read (ghost, fdt->close_on_exec, cpy);
		if (r)
			goto exit_free_files;
		memset((char *)(fdt->close_on_exec) + cpy, 0, set);

		r = ghost_read (ghost, fdt->open_fds, cpy);
		if (r)
			goto exit_free_files;
		memset((char *)(fdt->open_fds) + cpy, 0, set);
	}
	else {
		fdt = &files->fdtab;
		INIT_RCU_HEAD(&fdt->rcu);
		fdt->next = NULL;
		fdt->close_on_exec = (fd_set *)&files->close_on_exec_init;
		fdt->open_fds = (fd_set *)&files->open_fds_init;
		fdt->fd = &files->fd_array[0];
	}

	rcu_assign_pointer(files->fdt, fdt);

	tsk->files = files;

	{
		int magic = 0;

		r = ghost_read (ghost, &magic, sizeof (int));

		BUG_ON (!r && magic != 280574);
	}

	if (action->type == EPM_RESTART)
		r = cr_link_to_open_files(action, ghost, tsk, files,
					  fdt, last_open_fd);
	else
		r = import_open_files(action, ghost, tsk, files, fdt,
				      last_open_fd);

	if (r)
		goto exit_free_fdt;

	{
		int magic = 0;

		r = ghost_read (ghost, &magic, sizeof (int));

		BUG_ON (!r && magic != 380574);
	}

	return 0;

exit_free_fdt:
	if (import_fdt)
		free_fdtable(fdt);

exit_free_files:
	kmem_cache_free(files_cachep, files);
	epm_error(action, r, tsk,
		  "Fail to restore struct files_struct");

	return r;
}

static int cr_link_to_vma_phys_file(struct epm_action *action,
				    ghost_t *ghost,
				    struct task_struct *tsk,
				    struct vm_area_struct *vma,
				    struct file **file)
{
	int r;
	int anon_shared;

	r = ghost_read_type(ghost, anon_shared);
	if (r)
		goto exit;

	if (anon_shared) {
		vma->vm_file = NULL;
		r = shmem_zero_setup(vma);
		*file = vma->vm_file;
		goto exit;
	}

	r = cr_link_to_file(action, ghost, tsk, file);
	if (r)
		goto exit;

	if (vma->vm_flags & VM_EXEC) {

		/* to check it is the same file */

		loff_t old_file_size;
		loff_t current_file_size;

		r = ghost_read(ghost, &old_file_size, sizeof(loff_t));
		if (r)
			goto exit;

		r = get_file_size(*file, &current_file_size);
		if (r)
			goto exit;

		if (old_file_size != current_file_size) {
			printk("The application binary or libraries may have "
			       "changed since the checkpoint (%llu != %llu)\n",
			       old_file_size, current_file_size);
			r = -ENOEXEC;
		}
	}

exit:
	return r;
}

int import_vma_phys_file(struct epm_action *action,
			 ghost_t *ghost,
			 struct task_struct *tsk,
			 struct vm_area_struct *vma,
			 hashtable_t *file_table)
{
	unsigned long key;
	struct file *file;
	int import_file;
	int r;

	if (action->type == EPM_RESTART) {
		r = cr_link_to_vma_phys_file(action, ghost, tsk, vma, &file);
		if (r || is_anon_shared_mmap(file))
			goto err;
		goto map_file;
	}

	r = ghost_read(ghost, &key, sizeof(unsigned long));
	if (r)
		goto err;

	r = ghost_read(ghost, &import_file, sizeof(int));
	if (r)
		goto err;

	if (import_file) {
		/* First import ? Let's do the job ! */
		r = import_one_open_file(action, ghost, tsk,
					 MMAPPED_FILE, &file);
		if (r)
			goto err;

		r = __hashtable_add(file_table, key, file);
		if (r)
			goto err;

		/* Get a reference until mm import is done */
		get_file(file);
	}
	else {
		/* File has already been imported for another VMA: reuse it. */
		file = __hashtable_find(file_table, key);
		BUG_ON(file == NULL);
		get_file(file);
	}

map_file:
	vma->vm_file = file;
	if (file->f_op && file->f_op->mmap)
		r = file->f_op->mmap(file, vma);
	if (r)
		goto err;

err:
	return r;
}

/** Import the file associated to a VMA.
 *  @author Renaud Lottiaux
 *
 *  @param ghost    Ghost where data are be stored.
 *  @param tsk      The task to import VMA for.
 *  @param vma      The VMA to import the file in.
 *
 *  @return  0 if everything ok.
 *           Negative value otherwise.
 */
int import_vma_file (struct epm_action *action,
		     ghost_t *ghost,
                     struct task_struct *tsk,
                     struct vm_area_struct *vma,
		     hashtable_t *file_table)
{
	int vm_file_type;
	int r;

	/* Import the file type flag */
	r = ghost_read (ghost, &vm_file_type, sizeof (int));
	if (r)
		goto err_read;

	switch (vm_file_type) {
	  case VM_FILE_NONE:
		  vma->vm_file = NULL;
		  break;

	  case VM_FILE_PHYS:
		  r = import_vma_phys_file(action, ghost, tsk, vma,
					   file_table);
		  if (r)
			  goto err_read;
		  BUG_ON (!vma->vm_file);
		  break;

	  default:
		  BUG();
	}

err_read:
	return r;
}

int import_mm_exe_file(struct epm_action *action, ghost_t *ghost,
		       struct task_struct *tsk)
{
	int dump, r = 0;

	BUG_ON(action->type == EPM_RESTART
	       && action->restart.shared == CR_LINK_ONLY);

#ifdef CONFIG_PROC_FS
	r = ghost_read(ghost, &dump, sizeof(int));
	if (r)
		goto exit;

	if (dump) {
		if (action->type == EPM_RESTART)
			r = cr_link_to_file(action, ghost, tsk,
					    &tsk->mm->exe_file);
		else
			r = import_one_open_file(action, ghost, tsk, -1,
						 &tsk->mm->exe_file);
	}
exit:
#endif
	return r;
}

static int cr_link_to_fs_struct(struct epm_action *action,
				ghost_t *ghost,
				struct task_struct *tsk)
{
	int r;
	long key;
	struct fs_struct *fs;

	r = ghost_read(ghost, &key, sizeof(long));
	if (r)
		goto err;

	fs = get_imported_shared_object(action->restart.app,
					FS_STRUCT, key);

	if (!fs) {
		r = -E_CR_BADDATA;
		goto err;
	}

	/* the task is not yet hashed, no need to lock */
	fs->users++;
	tsk->fs = fs;
err:
	return r;
}

/** Import the fs_struct of a process
 *  @author Renaud Lottiaux
 *
 *  @param ghost  Ghost where file data are stored.
 *  @param tsk    Task to import file data in.
 *
 *  @return  0 if everything ok.
 *           Negative value otherwise.
 */
int import_fs_struct (struct epm_action *action,
		      ghost_t *ghost,
                      struct task_struct *tsk)
{
	struct fs_struct *fs;
	char *buffer;
	int r;

	if (action->type == EPM_RESTART
	    && action->restart.shared == CR_LINK_ONLY) {
		r = cr_link_to_fs_struct(action, ghost, tsk);
		return r;
	}

	buffer = (char *)__get_free_page(GFP_KERNEL);
	if (!buffer)
		return -ENOMEM;

	{
		int magic = 0;

		r = ghost_read (ghost, &magic, sizeof (int));
		BUG_ON (!r && magic != 55611);
	}

	r = -ENOMEM;
	fs = kmem_cache_alloc(fs_cachep, GFP_KERNEL);
	if (fs == NULL)
		goto exit;

	fs->users = 1;
	fs->in_exec = 0;
	rwlock_init (&fs->lock);

	/* Import the umask value */

	r = ghost_read(ghost, &fs->umask, sizeof (int));
	if (r)
		goto exit_free_fs;

	/* Import the root path name */

	r = populate_fs_struct(ghost, buffer, &fs->root);
	if (r)
		goto exit_free_fs;

	/* Import the pwd path name */

	r = populate_fs_struct(ghost, buffer, &fs->pwd);
	if (r)
		goto exit_put_root;

	{
		int magic = 0;

		r = ghost_read (ghost, &magic, sizeof (int));
		BUG_ON (!r && magic != 180574);
	}

	tsk->fs = fs;

exit:
	free_page ((unsigned long) buffer);
	if (r)
		epm_error(action, r, tsk,
			  "Fail to restore struct fs_struct");
	return r;

exit_put_root:
	path_put(&fs->root);

exit_free_fs:
	kmem_cache_free (fs_cachep, fs);
	goto exit;
}

int import_mnt_namespace(struct epm_action *action,
			 ghost_t *ghost, struct task_struct *tsk)
{
	/* TODO */
	tsk->nsproxy->mnt_ns = tsk->nsproxy->krg_ns->root_nsproxy.mnt_ns;
	get_mnt_ns(tsk->nsproxy->mnt_ns);

	return 0;
}

/*****************************************************************************/
/*                                                                           */
/*                            UNIMPORT FUNCTIONS                             */
/*                                                                           */
/*****************************************************************************/

void unimport_files_struct(struct task_struct *tsk)
{
	exit_files(tsk);
}

void unimport_fs_struct(struct task_struct *tsk)
{
	exit_fs(tsk);
}

/*****************************************************************************/
/*                                                                           */
/*                              INITIALIZATION                               */
/*                                                                           */
/*****************************************************************************/

int dvfs_mobility_init(void)
{
#ifdef CONFIG_KRG_FAF
	krgsyms_register(KRGSYMS_DVFS_MOBILITY_FAF_OPS,
			 &dvfs_mobility_faf_ops);
#endif
	krgsyms_register(KRGSYMS_DVFS_MOBILITY_REGULAR_OPS,
			 &dvfs_mobility_regular_ops);

	return 0;
}

void dvfs_mobility_finalize (void)
{
	krgsyms_unregister(KRGSYMS_DVFS_MOBILITY_REGULAR_OPS);
#ifdef CONFIG_KRG_FAF
	krgsyms_unregister(KRGSYMS_DVFS_MOBILITY_FAF_OPS);
#endif
}

static int cr_export_now_files_struct(struct epm_action *action, ghost_t *ghost,
				      struct task_struct *task,
				      union export_args *args)
{
	return export_files_struct(action, ghost, task);
}

static int cr_import_now_files_struct(struct epm_action *action, ghost_t *ghost,
				      struct task_struct *fake, int local_only,
				      void ** returned_data, size_t *data_size)
{
	int r;
	BUG_ON(*returned_data != NULL);

	r = import_files_struct(action, ghost, fake);
	if (r)
		goto err;

	*returned_data = fake->files;
err:
	return r;
}

static int cr_import_complete_files_struct(struct task_struct *fake,
					   void *_files)
{
	struct files_struct *files = _files;

	fake->files = files;
	exit_files(fake);

	return 0;
}

static int cr_delete_files_struct(struct task_struct *fake, void *_files)
{
	struct files_struct *files = _files;

	fake->files = files;
	exit_files(fake);

	return 0;
}

struct shared_object_operations cr_shared_files_struct_ops = {
        .export_now        = cr_export_now_files_struct,
	.export_user_info  = NULL,
	.import_now        = cr_import_now_files_struct,
	.import_complete   = cr_import_complete_files_struct,
	.delete            = cr_delete_files_struct,
};

static int cr_export_now_fs_struct(struct epm_action *action, ghost_t *ghost,
				   struct task_struct *task,
				   union export_args *args)
{
	return export_fs_struct(action, ghost, task);
}

static int cr_import_now_fs_struct(struct epm_action *action, ghost_t *ghost,
				   struct task_struct *fake, int local_only,
				   void ** returned_data, size_t *data_size)
{
	int r;
	BUG_ON(*returned_data != NULL);

	r = import_fs_struct(action, ghost, fake);
	if (r)
		goto err;
	*returned_data = fake->fs;
err:
	return r;
}

static int cr_import_complete_fs_struct(struct task_struct *fake, void *_fs)
{
	struct fs_struct *fs = _fs;

	fake->fs = fs;
	exit_fs(fake);

	return 0;
}

static int cr_delete_fs_struct(struct task_struct *fake, void *_fs)
{
	struct fs_struct *fs = _fs;

	fake->fs = fs;
	exit_fs(fake);

	return 0;
}

struct shared_object_operations cr_shared_fs_struct_ops = {
        .export_now        = cr_export_now_fs_struct,
	.export_user_info  = NULL,
	.import_now        = cr_import_now_fs_struct,
	.import_complete   = cr_import_complete_fs_struct,
	.delete            = cr_delete_fs_struct,
};
