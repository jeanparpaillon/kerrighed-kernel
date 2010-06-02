/** File Ghost interface.
 *  @file file_ghost.c
 *
 *  Copyright (C) 2001-2006, INRIA, Universite de Rennes 1, EDF.
 */
#include <linux/cred.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fdtable.h>
#include <linux/syscalls.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <kerrighed/dvfs.h>
#include <kerrighed/ghost.h>
#include <kerrighed/file_ghost.h>
#include <kerrighed/physical_fs.h>

/*--------------------------------------------------------------------------*
 *                                                                          *
 *  Functions to implement ghost interface                                  *
 *                                                                          *
 *--------------------------------------------------------------------------*/

/** Read data from a file ghost.
 *  @author Renaud Lottiaux, Geoffroy Vallée
 *
 *  @param  ghost   Ghost to read data from.
 *  @param  buff    Buffer to store data.
 *  @param  length  Size of data to read.
 *
 *  @return        0 if everything ok
 *                 Negative value otherwise.
 */
int file_ghost_read(ghost_t *ghost, void *buff, size_t length)
{
	struct file_ghost_data *ghost_data;
	struct file *file = NULL;
	loff_t pos;
	int r = 0;

	BUG_ON(!ghost);
	BUG_ON(!buff);

	ghost_data = (struct file_ghost_data *)ghost->data;

	file = ghost_data->file;
	BUG_ON(!file);

	pos = file_pos_read(file);
	r = vfs_read(file, (char*)buff, length, &pos);
	file_pos_write(file, pos);

	if (r == length)
		r = 0;
	else if (r >= 0)
		r = -EFAULT;
	return r ;
}

/** Write data to a file ghost.
 *  @author Renaud Lottiaux, Geoffroy Vallée
 *
 *  @param  ghost   Ghost to write data to.
 *  @param  buff    Buffer to write in the ghost.
 *  @param  length  Size of data to write.
 *
 *  @return        0 if everything ok
 *                 Negative value otherwise.
 */
int file_ghost_write(struct ghost *ghost, const void *buff, size_t length)
{
	struct file_ghost_data *ghost_data;
	struct file *file = NULL;
	loff_t pos;
	int r = 0;

	BUG_ON(!ghost);
	BUG_ON(!buff);

	ghost_data = (struct file_ghost_data *)ghost->data;
	BUG_ON(!ghost_data);

	file = ghost_data->file;
	BUG_ON(!file);

	pos = file_pos_read(file);
	r = vfs_write(file, (char*)buff, length, &pos);
	file_pos_write(file, pos);

	if (r == length)
		r = 0;
	else if (r >= 0)
		r = -EFAULT;

	return r ;
}

/** Close a ghost file
 *  @author Matthieu Fertré
 *
 *  @param  ghost    Ghost file to close
 */
int file_ghost_close(ghost_t *ghost)
{
	struct file *file;
	int r = 0;

	file = ((struct file_ghost_data *)ghost->data)->file;

	if (ghost->access & GHOST_WRITE
	    && file->f_op->fsync) {
		r = file->f_op->fsync(file, file->f_dentry, 1);
		if (r)
			printk("<0>-- WARNING -- (%s) : "
			       "Something wrong in the sync : %d\n",
			       __PRETTY_FUNCTION__, r);
	}

	if (((struct file_ghost_data *)ghost->data)->from_fd)
		fput(file);
	else
		filp_close(file, current->files);

	free_ghost(ghost);
	return r;
}

/** File ghost operations
 */
struct ghost_operations ghost_file_ops = {
	.read  = &file_ghost_read,
	.write = &file_ghost_write,
	.close = &file_ghost_close
};

void __set_ghost_fs(ghost_fs_t *oldfs)
{
	oldfs->fs = get_fs();
	set_fs(KERNEL_DS);
	oldfs->cred = NULL;
}

int set_ghost_fs(ghost_fs_t *oldfs, uid_t uid, gid_t gid)
{
	struct cred *new_cred;
	int r = -ENOMEM;

	new_cred = prepare_creds();
	if (!new_cred)
		goto err;
	new_cred->fsuid = uid;
	new_cred->fsgid = gid;

	__set_ghost_fs(oldfs);
	oldfs->cred = override_creds(new_cred);
	put_cred(new_cred);
	r = 0;

err:
	return r;
}

void unset_ghost_fs(const ghost_fs_t *oldfs)
{
	set_fs(oldfs->fs);
	if (oldfs->cred)
		revert_creds(oldfs->cred);
}

/*--------------------------------------------------------------------------*
 *                                                                          *
 * Macros and functions used to manage file ghost creation                  *
 *                                                                          *
 *--------------------------------------------------------------------------*/

// Path where file ghost are saved
#define CHECKPOINT_PATH "/var/chkpt/"
#define CHECKPOINT_PATH_LENGTH 45

char checkpointRoot[CHECKPOINT_PATH_LENGTH] = CHECKPOINT_PATH;

char *get_chkpt_dir(long app_id,
		    unsigned int chkpt_sn)
{
	char *buff;
	char *dirname;

	buff = kmalloc(PATH_MAX*sizeof(char), GFP_KERNEL);
	if (!buff) {
		dirname = ERR_PTR(-ENOMEM);
		goto err_buff;
	}

	dirname = kmalloc(PATH_MAX*sizeof(char), GFP_KERNEL);
	if (!dirname) {
		dirname = ERR_PTR(-ENOMEM);
		goto err_dirname;
	}

	snprintf(dirname, PATH_MAX, "%s", checkpointRoot);

	if (app_id) {
		snprintf(buff, PATH_MAX, "%ld/", app_id);
		strncat(dirname, buff, PATH_MAX);
	}

	if (chkpt_sn) {
		snprintf(buff, PATH_MAX, "v%d/", chkpt_sn);
		strncat(dirname, buff, PATH_MAX);
	}

err_dirname:
	kfree(buff);
err_buff:
	return dirname;
}

static char *__get_chkpt_filebase(long app_id,
				  unsigned int chkpt_sn,
				  const char *format,
				  va_list args)
{
	char *full_path;
	char *rel_path;

	full_path = get_chkpt_dir(app_id, chkpt_sn);
	if (IS_ERR(full_path))
		goto err;

	rel_path = kvasprintf(GFP_KERNEL, format, args);
	if (!rel_path) {
		kfree(full_path);
		full_path = ERR_PTR(-ENOMEM);
		goto err;
	}

	strncat(full_path, rel_path, PATH_MAX);

err:
	return full_path;
}

char *get_chkpt_filebase(long app_id,
			 unsigned int chkpt_sn,
			 const char *format,
			 ...)
{
	va_list args;
	char *filename;

	va_start(args, format);
	filename = __get_chkpt_filebase(app_id, chkpt_sn, format, args);
	va_end(args);

	return filename;
}

int mkdir_chkpt_path(long app_id, unsigned int chkpt_sn)
{
	char *buff;
	char *dirname;
	int r;

	buff = kmalloc(PATH_MAX*sizeof(char), GFP_KERNEL);
	if (!buff) {
		r = -ENOMEM;
		goto err_buff;
	}

	dirname = kmalloc(PATH_MAX*sizeof(char), GFP_KERNEL);
	if (!dirname) {
		r = -ENOMEM;
		goto err_dirname;
	}

	snprintf(dirname, PATH_MAX, "%s", checkpointRoot);

	if (app_id) {
		snprintf(buff, PATH_MAX, "%ld/", app_id);
		strncat(dirname, buff, PATH_MAX);
	}

	r = sys_mkdir(dirname, S_IRWXUGO|S_ISVTX);
	if (r && r != -EEXIST)
		goto err;

	/* really force the mode without looking at umask */
	r = sys_chmod(dirname, S_IRWXUGO|S_ISVTX);
	if (r)
		goto err;

	if (chkpt_sn) {
		snprintf(buff, PATH_MAX, "v%d/", chkpt_sn);
		strncat(dirname, buff, PATH_MAX);

		r = sys_mkdir(dirname, S_IRWXU);
		if (r && r != -EEXIST)
			goto err;
		r = 0;
	}

err:
	kfree(dirname);
err_dirname:
	kfree(buff);
err_buff:
	return r;
}

static ghost_t *__create_file_ghost(int access, struct file *file, int from_fd)
{
	ghost_t *ghost;
	struct file_ghost_data *ghost_data;
	int r;

	/* A file ghost can only be used in uni-directional mode */
	BUG_ON(!(!(access & GHOST_READ) ^ !(access & GHOST_WRITE)));

	ghost = create_ghost(GHOST_FILE, access);
	if (IS_ERR(ghost)) {
		r = PTR_ERR(ghost);
		goto err_file;
	}

	ghost_data = kmalloc(sizeof(struct file_ghost_data), GFP_KERNEL);
	if (!ghost_data) {
		r = -ENOMEM;
		goto err_ghost;
	}

	ghost_data->file = file;
	ghost_data->from_fd = from_fd;

	ghost->data = ghost_data;
	ghost->ops = &ghost_file_ops;

	return ghost;

err_ghost:
	free_ghost(ghost);

err_file:
	return ERR_PTR(r);
}

/** Create a new file ghost.
 *  @author Renaud Lottiaux, Matthieu Fertré
 *
 *  @param  access   Ghost access (READ/WRITE)
 *  @param  file     File to read/write data to/from.
 *
 *  @return        ghost_t if everything ok
 *                 ERR_PTR otherwise.
 */
ghost_t *create_file_ghost(int access,
			   long app_id,
			   unsigned int chkpt_sn,
			   const char *format,
			   ...)
{
	struct file *file;
	va_list args;
	char *filename;
	struct prev_root prev_root;

	ghost_t *ghost;
	int r;

	chroot_to_physical_root(&prev_root);

	/* Create directory if not exist */
	if (access & GHOST_WRITE) {
		r = mkdir_chkpt_path(app_id, chkpt_sn);
		if (r)
			goto err;
	}

	/* Create a ghost to host the checkpoint */
	va_start(args, format);
	filename = __get_chkpt_filebase(app_id, chkpt_sn, format, args);
	va_end(args);

	if (IS_ERR(filename)) {
		r = PTR_ERR(filename);
		goto err;
	}

	if (access & GHOST_WRITE)/* fail if already exists */
		file = filp_open(filename, O_CREAT|O_EXCL|O_WRONLY, S_IRUSR|S_IWUSR);
	else
		file = filp_open(filename, O_RDONLY, S_IRWXU);

	kfree(filename);

	if (IS_ERR(file)) {
		r = PTR_ERR(file);
		goto err;
	}

	/* Create a ghost to host the checkoint */
	ghost = __create_file_ghost(access, file, 0);
	if (IS_ERR(ghost)) {
		r = PTR_ERR(ghost);
		goto err_file;
	}

out:
	chroot_to_prev_root(&prev_root);

	return ghost;

err_file:
	filp_close(file, current->files);
err:
	ghost = ERR_PTR(r);
	goto out;
}

void unlink_file_ghost(ghost_t *ghost)
{
	struct file_ghost_data *ghost_data = ghost->data;
	struct dentry *dentry = ghost_data->file->f_dentry;
	struct inode *dir = dentry->d_parent->d_inode;

	BUG_ON(ghost_data->from_fd);

	mutex_lock_nested(&dir->i_mutex, I_MUTEX_PARENT);
	vfs_unlink(dir, dentry);
	mutex_unlock(&dir->i_mutex);
}

/** Create a new file ghost.
 *  @author Matthieu Fertré
 *
 *  @param  access   Ghost access (READ/WRITE)
 *  @param  file     File descriptor to read/write data to/from.
 *
 *  @return        ghost_t if everything ok
 *                 ERR_PTR otherwise.
 */
ghost_t *create_file_ghost_from_fd(int access, unsigned int fd)
{
	struct file *file;
	ghost_t *ghost;
	int r;

	file = fget(fd);
	if (!file) {
		r = -EBADF;
		goto err;
	}

	/* check the access right */
	if ((access & GHOST_WRITE && !(file->f_mode & FMODE_WRITE))
	    || (access & GHOST_READ && !(file->f_mode & FMODE_READ))) {
		r = -EACCES;
		goto err_file;
	}

	/* Create a ghost to host the checkoint */
	ghost = __create_file_ghost(access, file, 1);
	if (IS_ERR(ghost)) {
		r = PTR_ERR(ghost);
		goto err_file;
	}

	return ghost;

err_file:
	fput(file);
err:
	return ERR_PTR(r);
}

loff_t get_file_ghost_pos(ghost_t *ghost)
{
	struct file *file;

	file = ((struct file_ghost_data *)ghost->data)->file;

	return file->f_pos;
}

void set_file_ghost_pos(ghost_t *ghost, loff_t file_pos)
{
	struct file *file;

	file = ((struct file_ghost_data *)ghost->data)->file;
	file->f_pos = file_pos;
}
