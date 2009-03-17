/*
 *  Copyright (C) 2001-2006, INRIA, Universite de Rennes 1, EDF.
 *  Copyright (C) 2007, Louis Rilling - Kerlabs.
 */

#include <linux/proc_fs.h>
#include <linux/procfs_internal.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/uaccess.h>
#include <kerrighed/task.h>

#include "proc_pid.h"
#include "proc_pid_link.h"

static int krg_proc_fd_access_allowed(struct inode *inode)
{
	struct proc_distant_pid_info *task = get_krg_proc_task(inode);
/* 	struct task_kddm_object *obj; */
	const struct cred *cred = current_cred();
	int allowed = 0;

/* 	obj = krg_task_readlock(task->pid); */
/* 	if (obj) { */
		if (((cred->uid != task->euid) ||
/*		     (cred->uid != obj->suid) || */
/* 		     (cred->uid != obj->uid) || */
		     (cred->gid != task->egid)/*  || */
/*		     (cred->gid != obj->sgid) || */
/*		     (cred->gid != obj->gid) */) && !capable(CAP_SYS_PTRACE))
			allowed = -EPERM;
		if (!task->dumpable && !capable(CAP_SYS_PTRACE))
			allowed = -EPERM;
/* 	} */
/* 	krg_task_unlock(task->pid); */
	return allowed;
}

static void *krg_proc_pid_follow_link(struct dentry *dentry,
				      struct nameidata *nd)
{
	struct inode *inode = dentry->d_inode;
	int error = -EACCES;

	/* We don't need a base pointer in the /proc filesystem */
	path_put(&nd->path);

	/* Are we allowed to snoop on the tasks file descriptors? */
	if (!krg_proc_fd_access_allowed(inode))
		goto out;

	error = get_krg_proc_task(inode)->op.proc_get_link(inode, &nd->path);
	nd->last_type = LAST_BIND;
out:
	return ERR_PTR(error);
}

static int krg_proc_pid_readlink(struct dentry *dentry,
				 char __user *buffer, int buflen)
{
	int error = -EACCES;
	struct inode *inode = dentry->d_inode;
	struct path path;

	/* Are we allowed to snoop on the tasks file descriptors? */
	if (!krg_proc_fd_access_allowed(inode))
		goto out;

	error = get_krg_proc_task(inode)->op.proc_get_link(inode, &path);
	if (error)
		goto out;

	error = do_proc_readlink(&path, buffer, buflen);
	path_put(&path);
out:
	return error;
}

struct inode_operations krg_proc_pid_link_inode_operations = {
	.readlink = krg_proc_pid_readlink,
	.follow_link = krg_proc_pid_follow_link,
	.setattr = proc_setattr,
};

int krg_proc_exe_link(struct inode *inode, struct path *path)
{
	return 0;
}

int krg_proc_cwd_link(struct inode *inode, struct path *path)
{
	return 0;
}

int krg_proc_root_link(struct inode *inode, struct path *path)
{
	/* should increment fs of task at distance */
	return 0;
}
