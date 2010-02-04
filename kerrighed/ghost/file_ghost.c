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
#include <kerrighed/ghost.h>
#include <kerrighed/file_ghost.h>
#include <kerrighed/physical_fs.h>
#ifdef CONFIG_KRG_FAF
#include <kerrighed/faf.h>
#endif

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
	struct file_ghost_data *ghost_data ;
	struct file *file = NULL;
	int r = 0 ;

	BUG_ON(!ghost);
	BUG_ON(!buff);

	ghost_data = (struct file_ghost_data *)ghost->data;

	file = ghost_data->file;
	BUG_ON(!file);

#ifdef CONFIG_KRG_FAF
	if (file->f_flags & O_FAF_CLT)
		r = krg_faf_read(file, (char*)buff, length);
	else
#endif
		r = file->f_op->read(file, (char*)buff, length, &file->f_pos);

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
	struct file_ghost_data *ghost_data ;
	struct file *file = NULL;
	int r = 0 ;

	BUG_ON(!ghost);
	BUG_ON(!buff);

	ghost_data = (struct file_ghost_data *)ghost->data;
	BUG_ON(!ghost_data);

	file = ghost_data->file;
	BUG_ON(!file);

#ifdef CONFIG_KRG_FAF
	if (file->f_flags & O_FAF_CLT)
		r = krg_faf_write(file, (char*)buff, length);
	else
#endif
		r = file->f_op->write(file, (char*)buff, length, &file->f_pos);

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

	file = ((struct file_ghost_data *)ghost->data)->file;

	if (ghost->access & GHOST_WRITE) {
#if 0
		do_fdatasync(file);
#else
		if (file->f_op->fsync) {
			int r = file->f_op->fsync(file, file->f_dentry, 1);
			if (r)
				printk("<0>-- WARNING -- (%s) : "
				       "Something wrong in the sync : %d\n",
				       __PRETTY_FUNCTION__, r);
		}
#endif
	}

	if (((struct file_ghost_data *)ghost->data)->from_fd)
		fput(file);
	else
		filp_close(file, current->files);

	return free_ghost(ghost);
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


char *get_chkpt_filebase(const char *format, ...)
{
	va_list args;
	char *filename;

	va_start(args, format);
	filename = kvasprintf(GFP_KERNEL, format, args);
	va_end(args);

	if (!filename)
		filename = ERR_PTR(-ENOMEM);

	return filename;
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
ghost_t *create_file_ghost(int access, const char *format, ...)
{
	struct file *file;
	va_list args;
	char *filename;
	struct path prev_root;

	ghost_t *ghost;
	int r;

	chroot_to_physical_root(&prev_root);

	/* Create a ghost to host the checkoint */
	va_start(args, format);
	filename = kvasprintf(GFP_KERNEL, format, args);
	va_end(args);

	if (!filename) {
		r = -ENOMEM;
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
