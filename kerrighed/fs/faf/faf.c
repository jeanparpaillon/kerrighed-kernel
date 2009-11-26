/** Kerrighed Open File Access Forwarding System.
 *  @file faf.c
 *
 *  Copyright (C) 2001-2006, INRIA, Universite de Rennes 1, EDF.
 *  Copyright (C) 2006-2007, Renaud Lottiaux, Kerlabs.
 */
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/magic.h>
#include <linux/socket.h>
#include <linux/sched.h>

#include <net/krgrpc/rpc.h>
#include <kerrighed/action.h>
#include <kerrighed/faf.h>
#include <kerrighed/file.h>
#include "faf_internal.h"
#include "faf_server.h"
#include "faf_hooks.h"

extern struct kmem_cache *faf_client_data_cachep;

/*****************************************************************************/
/*                                                                           */
/*                             INTERFACE FUNCTIONS                           */
/*                                                                           */
/*****************************************************************************/

/** Add a file in the FAF daemon.
 *  @author Renaud Lottiaux
 *
 *  @param file       The file to add in the FAF daemon
 *
 *  @return   0 if everything ok.
 *            Negative value otherwise.
 */
int setup_faf_file(struct file *file)
{
	int server_fd = 0;
	int res = 0;

	/* Install the file in the destination task file array */

	if (!test_and_set_bit(O_FAF_SRV_BIT_NR, &file->f_flags)) {
		server_fd = __get_unused_fd(first_krgrpc);

		if (server_fd >= 0) {
			get_file (file);
			file->f_faf_srv_index = server_fd;
			file->f_flags |= O_FAF_SRV;
			__fd_install(first_krgrpc->files, server_fd, file);
		}
		else
			res = server_fd;
	}
	else
		res = -EALREADY;

	return res;
}

/** Close a file in the FAF deamon.
 *  @author Renaud Lottiaux
 *
 *  @param file    The file to close.
 */
int close_faf_file(struct file * file)
{
        struct files_struct *files = first_krgrpc->files;
        struct file * faf_file;
        struct fdtable *fdt;
        int fd = file->f_faf_srv_index;

	BUG_ON (!(file->f_flags & O_FAF_SRV));
	BUG_ON (file_count(file) != 1);

	/* Remove the file from the FAF server file table */

	spin_lock(&files->file_lock);

        fdt = files_fdtable(files);
        if (fd >= fdt->max_fds)
                BUG();
        faf_file = fdt->fd[fd];
        if (!faf_file)
                BUG();
        BUG_ON (faf_file != file);

        rcu_assign_pointer(fdt->fd[fd], NULL);
        FD_CLR(fd, fdt->close_on_exec);
        __put_unused_fd(files, fd);

	spin_unlock(&files->file_lock);

	/* Cleanup Kerrighed flags but not objid to pass through the regular
	 * kernel close file code plus kh_put_file() only.
	 */
	file->f_flags = file->f_flags & (~O_FAF_SRV);

        return filp_close(faf_file, files);
}

/** Check if we need to close a FAF server file.
 *  @author Renaud Lottiaux
 *
 *  @param file         The file to check.
 *
 *  We can close a FAF server file if local f_count == 1 and DVFS count == 1.
 *  This means the FAF server is the last process cluster wide using the file.
 */
void check_close_faf_srv_file(struct file *file)
{
	struct dvfs_file_struct *dvfs_file;
	unsigned long objid = file->f_objid;
	int close_file = 0;

	/* Pre-check the file count to avoid a useless call to get_dvfs */
	if (file_count (file) != 1)
		return;

	dvfs_file = get_dvfs_file_struct(objid);
	/* If dvfs file is NULL, someone else did the job before us */
	if (dvfs_file->file == NULL)
		goto done;
	BUG_ON (dvfs_file->file != file);

	/* Re-check f_count in case it changed during the get_dvfs */
	if ((dvfs_file->count == 1) && (file_count (file) == 1)) {
		/* The FAF server file is the last one used in the cluster.
		 * We can now close it.
		 */
		close_file = 1;
		dvfs_file->file = NULL;
	}

done:
	put_dvfs_file_struct (objid);

	if (close_file)
		close_faf_file(file);
}

void free_faf_file_private_data(struct file *file)
{
	if (!(file->f_flags & O_FAF_CLT))
		return;

	kmem_cache_free (faf_client_data_cachep, file->private_data);
	file->private_data = NULL;
}

/** Check if we are closing the last FAF client file.
 *  @author Renaud Lottiaux
 *
 *  @param file         The file attached to the DVFS struct.
 *  @param dvfs_file    The DVFS file struct being put.
 */
void check_last_faf_client_close(struct file *file,
				 struct dvfs_file_struct *dvfs_file)
{
	faf_client_data_t *data;
	struct faf_notify_msg msg;

	if(!(file->f_flags & O_FAF_CLT))
		return;

	/* If DVFS count == 1, there is no more FAF clients, the last count
	 * being for the FAF server node. In this case, notify the FAF server
	 * to let it check if it should close the FAF file or not.
	 */
	if (dvfs_file->count == 1) {
		data = file->private_data;
		msg.server_fd = data->server_fd;
		msg.objid = file->f_objid;

		rpc_async(RPC_FAF_NOTIFY_CLOSE, data->server_id,
			  &msg, sizeof(msg));
	}

	free_faf_file_private_data(file);
}

int setup_faf_file_if_needed(struct file *file)
{
	int r = 0;

	/* Check if the file is already a FAF file */
	if (file->f_flags & (O_FAF_CLT | O_FAF_SRV))
		goto exit;

	/* Check if we can re-open the file */
	if (file->f_dentry) {
		umode_t i_mode = file->f_dentry->d_inode->i_mode;
		unsigned long s_magic = file->f_dentry->d_sb->s_magic;

		if (((s_magic == PROC_SUPER_MAGIC) ||
		     (s_magic == NFS_SUPER_MAGIC)  ||
		     (s_magic == OCFS2_SUPER_MAGIC)) &&
		    (S_ISREG(i_mode) || S_ISDIR(i_mode) || S_ISLNK(i_mode)))
			goto exit;
	}

	/* Ok, so, we cannot do something better then using the FAF.
	 * Let's do it !
	 */
	r = setup_faf_file(file);
exit:
	return r;
}

void check_activate_faf (struct task_struct *tsk,
			 int index,
			 struct file *file,
			 struct epm_action *action)
{

	/* Index < 0 means a mapped file. We do not use FAF for this  */
	if (index < 0)
		goto done;

	/* No need to activate FAF for a checkpoint */
	if (action->type == EPM_CHECKPOINT)
		goto done;

/* 	if (file->f_dentry && */
/* 	    file->f_dentry->d_inode && */
/* 	    file->f_dentry->d_inode->i_mapping && */
/* 	    file->f_dentry->d_inode->i_mapping->a_ctnr != NULL) */
/* 		activate_faf = 0; */

	setup_faf_file_if_needed(file);

done:
	return;
}

/*****************************************************************************/
/*                                                                           */
/*                              INITIALIZATION                               */
/*                                                                           */
/*****************************************************************************/

/* FAF Initialisation */

extern int ruaccess_start(void);
extern void ruaccess_exit(void);

void faf_init ()
{
	printk("FAF: initialisation : start\n");

	faf_client_data_cachep = kmem_cache_create("faf_client_data",
						   sizeof(faf_client_data_t),
						   0, SLAB_PANIC, NULL);

	ruaccess_start();
	faf_server_init();
	faf_hooks_init();

	printk("FAF: initialisation : done\n");
}



/* FAF Finalization */

void faf_finalize ()
{
	faf_hooks_finalize();
	faf_server_finalize();
	ruaccess_exit();
}
