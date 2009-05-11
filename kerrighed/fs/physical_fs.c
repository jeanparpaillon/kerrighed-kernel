/** Access to Physical File System management.
 *  @file physical_fs.c
 *
 *  Copyright (C) 2001-2006, INRIA, Universite de Rennes 1, EDF.
 *  Copyright (C) 2006-2007, Renaud Lottiaux, Kerlabs.
 *
 *  @author Renaud Lottiaux
 */

#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/dcache.h>
#include <linux/fs_struct.h>
#include <linux/sched.h>
#include <linux/module.h>
#ifdef CONFIG_X86_64
#include <asm/ia32.h>
#endif
#include <linux/file.h>
#include <linux/namei.h>

#include "physical_fs.h"

char *physical_d_path(const struct path *path, char *tmp)
{
	char *pathname;
	int len;

	pathname = __d_path(path, &init_task.fs->root, tmp, PAGE_SIZE);

	if (IS_ERR(pathname))
		return NULL;

	len = strlen(pathname);
	if (len >= 10) {
		if (strcmp (pathname + len - 10, " (deleted)") == 0)
			pathname[len - 10] = 0;
	}

	return pathname;
}

struct file *open_physical_file (char *filename,
                                 int flags,
                                 int mode,
                                 uid_t fsuid,
                                 gid_t fsgid)
{
	const struct cred *old_cred;
	struct cred *override_cred;
	struct path old_root;
	struct file *file;

	/* no need to lock the fs_struct: we are in a kernel-thread importing
	   file from the ghost */
	old_root = current->fs->root;

	override_cred = prepare_creds();
	if (!override_cred)
		return ERR_PTR(-ENOMEM);

	override_cred->fsuid = fsuid;
	override_cred->fsgid = fsgid;
	old_cred = override_creds(override_cred);

	read_lock(&init_task.fs->lock);
	current->fs->root = init_task.fs->root;
	read_unlock(&init_task.fs->lock);

	file = filp_open (filename, flags, mode);

	revert_creds(old_cred);
	put_cred(override_cred);

	current->fs->root = old_root;

	return file;
}

int close_physical_file (struct file *file)
{
	int res;

	res = filp_close (file, current->files);

	return res;
}

int remove_physical_file (struct file *file)
{
	struct dentry *dentry;
	struct inode *dir;
	int res = 0;

	dentry = file->f_dentry;
	dir = dentry->d_parent->d_inode;

	res = vfs_unlink (dir, dentry);
	dput (dentry);
	put_filp (file);

	return res;
}

int remove_physical_dir (struct file *file)
{
	struct dentry *dentry;
	struct inode *dir;
	int res = 0;

	dentry = file->f_dentry;
	dir = dentry->d_parent->d_inode;

	res = vfs_rmdir (dir, dentry);
	dput (dentry);
	put_filp (file);

	return res;
}
