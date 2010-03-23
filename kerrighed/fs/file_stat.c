/*
 * Get information about file
 *
 * Copyright (C) 2009, Matthieu Fertré, Kerlabs.
 */

#include <linux/file.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/stat.h>
#include <kerrighed/fcntl.h>
#include <kerrighed/file.h>
#include <kerrighed/file_stat.h>
#include <kerrighed/physical_fs.h>
#ifdef CONFIG_KRG_FAF
#include <kerrighed/faf.h>
#include "faf/faf_internal.h"
#endif

static inline umode_t get_inode_mode(const struct file *file)
{
	umode_t i_mode;

#ifdef CONFIG_KRG_FAF
	if (file->f_flags & O_FAF_CLT)
		i_mode = ((struct faf_client_data*)file->private_data)->i_mode;
	else
#endif
		i_mode = file->f_dentry->d_inode->i_mode;

	return i_mode;
}

int is_pipe(const struct file *file)
{
	return S_ISFIFO(get_inode_mode(file));
}

static int __is_pipe_named(const struct file *file)
{
#ifdef CONFIG_KRG_FAF
	if (file->f_flags & O_FAF_CLT)
		return ((struct faf_client_data*)file->private_data)->is_named_pipe;
#endif

	return strlen(file->f_dentry->d_name.name);
}

int is_anonymous_pipe(const struct file *file)
{
	if (!is_pipe(file))
		return 0;

	return (!__is_pipe_named(file));
}

int is_named_pipe(const struct file *file)
{
	if (!is_pipe(file))
		return 0;

	return (__is_pipe_named(file));
}

int is_socket(const struct file *file)
{
	return S_ISSOCK(get_inode_mode(file));
}

int is_shm(const struct file *file)
{
	return (file->f_op == &shm_file_operations);
}

int is_char_device(const struct file *file)
{
	return S_ISCHR(get_inode_mode(file));
}

int is_block_device(const struct file *file)
{
	return S_ISBLK(get_inode_mode(file));
}

int is_directory(const struct file *file)
{
	return S_ISDIR(get_inode_mode(file));
}

int is_link(const struct file *file)
{
	return S_ISLNK(get_inode_mode(file));
}

extern const struct file_operations tty_fops;
extern const struct file_operations hung_up_tty_fops;

int is_tty(const struct file *file)
{
	int r = 0;

	if (!file)
		return 0;

	if (file->f_flags & O_FAF_CLT) {
		if (file->f_flags & O_FAF_TTY)
			r = 1;
	} else if (file->f_op == &tty_fops
		   || file->f_op == &hung_up_tty_fops)
		r = 1;

	return r;
}

char *get_phys_filename(struct file *file, char *buffer)
{
	char *filename;

#ifdef CONFIG_KRG_FAF
	if (file->f_flags & O_FAF_CLT) {
		filename = krg_faf_d_path(file, buffer, PAGE_SIZE);
		if (IS_ERR(filename))
			filename = NULL;
	} else
#endif
		filename = physical_d_path(&file->f_path, buffer);

	return filename;
}

char *get_filename(struct file *file, char *buffer)
{
	char *filename;

	if (file->f_path.dentry && file->f_path.dentry->d_op
	    && file->f_path.dentry->d_op->d_dname) {
		filename = file->f_path.dentry->d_op->d_dname(
				file->f_path.dentry, buffer, PAGE_SIZE);
		if (IS_ERR(filename))
			filename = NULL;
		return filename;
	}

	return get_phys_filename(file, buffer);
}

int can_checkpoint_file(const struct file *file)
{
	if (is_socket(file)) {
		printk("Checkpoint of socket file is not supported\n");
		return 0;
	} else if (is_named_pipe(file)) {
		printk("Checkpoint of FIFO file (nammed pipe) is not supported\n");
		return 0;
	}

	return 1;
}
