/** Global /proc/<pid>/fd management
 *  @file proc_pid_fd.c
 *
 *  Copyright (C) 2001-2006, INRIA, Universite de Rennes 1, EDF.
 *  Copyright (C) 2007, Louis Rilling - Kerlabs.
 */

#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/procfs_internal.h>

#include "proc_pid.h"

static int krg_proc_readfd(struct file *filp, void *dirent, filldir_t filldir)
{
	return 0;
}

struct file_operations krg_proc_fd_operations = {
	.read = generic_read_dir,
	.readdir = krg_proc_readfd,
};

static struct dentry *krg_proc_lookupfd(struct inode *dir,
					struct dentry *dentry,
					struct nameidata *nd)
{
	return ERR_PTR(-ENOENT);
}

/*
 * proc directories can do almost nothing..
 */
struct inode_operations krg_proc_fd_inode_operations = {
	.lookup = krg_proc_lookupfd,
	.setattr = proc_setattr,
};
