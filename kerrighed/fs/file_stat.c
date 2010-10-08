/*
 * Get information about file
 *
 * Copyright (C) 2009, Matthieu Fertré, Kerlabs.
 */

#include <linux/file.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/mount.h>
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

int is_anon_shared_mmap(const struct file *file)
{
	if (file->f_flags)
		return 0;

	if (file->f_op != &shmem_file_operations)
		return 0;

	if (file->f_path.mnt->mnt_ns)
		return 0;

	BUG_ON(strcmp("dev/zero", file->f_dentry->d_name.name) != 0);

	return 1;
}

extern const struct file_operations mqueue_file_operations;

int is_posix_mqueue(const struct file *file)
{
	if (file->f_op == &mqueue_file_operations)
		return 1;

	return 0;
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

extern const struct file_operations eventpoll_fops;

int is_eventpoll(const struct file *file)
{
	if (file->f_op == &eventpoll_fops)
		return 1;

	return 0;
}

extern const struct file_operations signalfd_fops;

int is_signal(const struct file *file)
{
	if (file->f_op == &signalfd_fops)
		return 1;

	return 0;
}

extern const struct file_operations timerfd_fops;

int is_timer(const struct file *file)
{
	if (file->f_op == &timerfd_fops)
		return 1;

	return 0;
}

char *get_phys_filename(const struct file *file, char *buffer, bool del_ok)
{
	char *filename;

#ifdef CONFIG_KRG_FAF
	if (file->f_flags & O_FAF_CLT) {
		bool deleted = false;
		bool *deleted_param = del_ok ? NULL : &deleted;

		filename = krg_faf_phys_d_path(file, buffer, PAGE_SIZE,
					       deleted_param);
		if ((!del_ok && deleted) || IS_ERR(filename))
			filename = NULL;
	} else
#endif
		filename = physical_d_path(&file->f_path, buffer, del_ok);

	return filename;
}

char *get_filename(const struct file *file, char *buffer)
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

	return get_phys_filename(file, buffer, true);
}

char *alloc_filename(const struct file *file, char **buffer)
{
	char *file_name;

	*buffer = (char *)__get_free_page(GFP_KERNEL);
	if (!*buffer) {
		file_name = ERR_PTR(-ENOMEM);
		goto exit;
	}

	file_name = get_filename(file, *buffer);
	if (!file_name) {
		file_name = *buffer;
		sprintf(file_name, "?");
	}

exit:
	return file_name;
}

void free_filename(char *buffer)
{
	free_page((unsigned long)buffer);
}

int can_checkpoint_file(const struct file *file)
{
	if (is_socket(file)) {
		pr_kerrighed("Checkpoint of socket file "
			     "is not supported\n");
		return 0;
	} else if (is_named_pipe(file)) {
		pr_kerrighed("Checkpoint of FIFO file (nammed pipe) "
			     "is not supported\n");
		return 0;
	} else if (is_posix_mqueue(file)) {
		pr_kerrighed("Checkpoint of posix message queue "
			     "is not supported\n");
		return 0;
	} else if (is_anon_shared_mmap(file)) {
		pr_kerrighed("Checkpoint of anonymous shared mmap file "
			     "is not supported\n");
		return 0;
	} else if (is_eventpoll(file)) {
		pr_kerrighed("Checkpoint of eventpoll file "
			     "is not supported\n");
		return 0;
	} else if (is_timer(file)) {
		pr_kerrighed("Checkpoint of timerfd file "
			     "is not supported\n");
		return 0;
	} else if (is_signal(file)) {
		pr_kerrighed("Checkpoint of signalfd file "
			     "is not supported\n");
		return 0;
	}

	return 1;
}

int can_faf_file(const struct file *file)
{
	if (is_posix_mqueue(file)) {
		pr_kerrighed("Export of posix message queue "
			     "is not supported\n");
		return 0;
	} else if (is_anon_shared_mmap(file)) {
		pr_kerrighed("Export of anonymous shared mmap file "
			     "is not supported\n");
		return 0;
	} else if (is_timer(file)) {
		pr_kerrighed("Export of timerfd file "
			     "is not supported\n");
		return 0;
	} else if (is_signal(file)) {
		pr_kerrighed("Export of signalfd file "
			     "is not supported\n");
		return 0;
	}

	return 1;
}
