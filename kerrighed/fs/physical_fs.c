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
#include <linux/mnt_namespace.h>
#include <linux/dcache.h>
#include <linux/fs_struct.h>
#include <linux/sched.h>
#include <linux/module.h>
#ifdef CONFIG_X86_64
#include <asm/ia32.h>
#endif
#include <linux/file.h>
#include <linux/namei.h>
#include <kerrighed/physical_fs.h>
#include <kerrighed/namespace.h>

char *physical_d_path(const struct path *path, char *tmp)
{
	struct path ns_root;
	char *pathname;

	/* Mnt namespace is already pinned by path->mnt */
	if (!path->mnt->mnt_ns)
		/* Not exportable */
		return NULL;

	ns_root.mnt = path->mnt->mnt_ns->root;
	ns_root.dentry = ns_root.mnt->mnt_root;
	spin_lock(&dcache_lock);
	pathname = __d_path(path, &ns_root, tmp, PAGE_SIZE);
	spin_unlock(&dcache_lock);
	BUG_ON(ns_root.mnt != path->mnt->mnt_ns->root
	       || ns_root.dentry != ns_root.mnt->mnt_root);

	if (IS_ERR(pathname))
		return NULL;

	return pathname;
}

void get_physical_root(struct path *root)
{
	struct krg_namespace *krg_ns = find_get_krg_ns();

	BUG_ON(!krg_ns);
	root->mnt = krg_ns->root_nsproxy.mnt_ns->root;
	root->dentry = root->mnt->mnt_root;
	path_get(root);
	put_krg_ns(krg_ns);

	while (d_mountpoint(root->dentry) &&
	       follow_down(&root->mnt, &root->dentry))
		;
}

void chroot_to_physical_root(struct prev_root *prev_root)
{
	struct krg_namespace *krg_ns = find_get_krg_ns();
	struct path root;

	BUG_ON(!krg_ns);
	BUG_ON(current->fs->users != 1);

	get_physical_root(&root);
	write_lock(&current->fs->lock);
	prev_root->path = current->fs->root;
	current->fs->root = root;
	write_unlock(&current->fs->lock);

	BUG_ON(prev_root->path.mnt->mnt_ns != current->nsproxy->mnt_ns);
	prev_root->nsproxy = current->nsproxy;
	rcu_assign_pointer(current->nsproxy, &krg_ns->root_nsproxy);
}

void chroot_to_prev_root(const struct prev_root *prev_root)
{
	struct path root;

	write_lock(&current->fs->lock);
	root = current->fs->root;
	current->fs->root = prev_root->path;
	write_unlock(&current->fs->lock);
	path_put(&root);

	rcu_assign_pointer(current->nsproxy, prev_root->nsproxy);
}

struct file *open_physical_file (char *filename,
                                 int flags,
                                 int mode,
                                 uid_t fsuid,
                                 gid_t fsgid)
{
	const struct cred *old_cred;
	struct cred *override_cred;
	struct prev_root prev_root;
	struct file *file;

	override_cred = prepare_creds();
	if (!override_cred)
		return ERR_PTR(-ENOMEM);

	override_cred->fsuid = fsuid;
	override_cred->fsgid = fsgid;
	old_cred = override_creds(override_cred);

	chroot_to_physical_root(&prev_root);

	file = filp_open (filename, flags, mode);

	chroot_to_prev_root(&prev_root);

	revert_creds(old_cred);
	put_cred(override_cred);

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
