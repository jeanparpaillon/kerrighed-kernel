/*
 *  Kerrighed/modules/ipc/mobility.c
 *
 *  Copyright (C) 2007 Louis Rilling - Kerlabs
 *  Copyright (C) 2007-2008 Matthieu Fertré - INRIA
 */

#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <linux/ima.h>
#include <linux/ipc.h>
#include <linux/ipc_namespace.h>
#include <linux/file.h>
#include <linux/msg.h>
#include <linux/security.h>
#include <linux/sem.h>
#include <linux/shm.h>
#include <linux/unique_id.h>
#include <kddm/kddm.h>
#include <kerrighed/namespace.h>
#include <kerrighed/ghost.h>
#include <kerrighed/ghost_helpers.h>
#include <kerrighed/action.h>
#include <kerrighed/application.h>
#include <kerrighed/app_shared.h>
#include <kerrighed/regular_file_mgr.h>
#include "ipc_handler.h"
#include "krgipc_mobility.h"
#include "krgshm.h"
#include "krgmsg.h"
#include "krgsem.h"
#include "sem_handler.h"
#include "semundolst_io_linker.h"

extern struct kddm_set *sem_undo_list_kddm_set;

/** Return a kerrighed descriptor corresponding to the given file.
 *  @author Renaud Lottiaux
 *
 *  @param file       The file to get a Kerrighed descriptor for.
 *  @param desc       The returned descriptor.
 *  @param desc_size  Size of the returned descriptor.
 *
 *  @return   0 if everything ok.
 *            Negative value otherwise.
 */
int get_shm_file_krg_desc (struct file *file,
			   void **desc,
			   int *desc_size)
{
	regular_file_krg_desc_t *data;
	int size, r = -ENOENT;

	size = sizeof (regular_file_krg_desc_t);

	data = kmalloc (size, GFP_KERNEL);
	if (!data) {
		r = -ENOMEM;
		goto exit;
	}

	data->sysv = 1;
	data->shm.shmid = file->f_dentry->d_inode->i_ino;
	data->shm.f_mode = file->f_mode;
	*desc = data;
	*desc_size = size;

	r = 0;
exit:
	return r;
}

struct file *reopen_shm_file_entry_from_krg_desc(struct task_struct *task,
						 void *_desc)
{
	int shmid;
	int err = 0;
	struct shmid_kernel *shp;
	struct shm_file_data *sfd;
	struct file *file = NULL;
	regular_file_krg_desc_t *desc = _desc;
	struct ipc_namespace *ns;
	struct path path;

	BUG_ON (!task);
	BUG_ON (!desc);

	ns = find_get_krg_ipcns();
	BUG_ON(!ns);

	shmid = desc->shm.shmid;

	down_read(&shm_ids(ns).rw_mutex);
	shp = shm_lock_check(ns, shmid);
	if (IS_ERR(shp)) {
		err = PTR_ERR(shp);
		up_read(&shm_ids(ns).rw_mutex);
		goto out;
	}

	path.dentry = dget(shp->shm_file->f_path.dentry);
	path.mnt    = shp->shm_file->f_path.mnt;
	shm_unlock(shp);
	up_read(&shm_ids(ns).rw_mutex);

	sfd = kzalloc(sizeof(*sfd), GFP_KERNEL);
	if (!sfd) {
		err = -ENOMEM;
		goto out_put_dentry;
	}

	file = alloc_file(path.mnt, path.dentry, desc->shm.f_mode,
			  &shm_file_operations);
	if (!file) {
		err = -ENOMEM;
		goto out_free;
	}
	ima_shm_check(file);

	file->private_data = sfd;
	file->f_mapping = shp->shm_file->f_mapping;

	sfd->id = shp->shm_perm.id;
	sfd->ns = get_ipc_ns(ns);
	sfd->file = shp->shm_file;
	sfd->file->private_data = sfd;
	sfd->vm_ops = &krg_shmem_vm_ops;
out:
	put_ipc_ns(ns);

	if (err)
		file = ERR_PTR(err);

	return file;

out_free:
	kfree(sfd);
out_put_dentry:
	dput(path.dentry);

	down_write(&shm_ids(ns).rw_mutex);
	shp = shm_lock(ns, shmid);
	BUG_ON(IS_ERR(shp));
	shp->shm_nattch--;
	if (shp->shm_nattch == 0 &&
	    shp->shm_perm.mode & SHM_DEST)
		krg_ipc_shm_destroy(ns, shp);
	else
		shm_unlock(shp);
	up_write(&shm_ids(ns).rw_mutex);

	goto out;
}

int export_ipc_namespace(struct epm_action *action,
			 ghost_t *ghost, struct task_struct *task)
{
	if (task->nsproxy->ipc_ns != task->nsproxy->krg_ns->root_ipc_ns)
		return -EPERM;

	return 0;
}

int import_ipc_namespace(struct epm_action *action,
			 ghost_t *ghost, struct task_struct *task)
{
	task->nsproxy->ipc_ns = find_get_krg_ipcns();
	BUG_ON(!task->nsproxy->ipc_ns);

	return 0;
}

void unimport_ipc_namespace(struct task_struct *task)
{
	put_ipc_ns(task->nsproxy->ipc_ns);
}


static int cr_export_later_sysv_sem(struct epm_action *action,
				    ghost_t *ghost,
				    struct task_struct *task)
{
	int r;
	long key;

	BUG_ON(action->type != EPM_CHECKPOINT);
	BUG_ON(action->checkpoint.shared != CR_SAVE_LATER);

	/* if this is not true anymore, it's time to change
	   this implementation ... */
	BUG_ON(sizeof(unique_id_t) != sizeof(long));

	key = (long)(task->sysvsem.undo_list_id);

	r = ghost_write(ghost, &key, sizeof(long));
	if (r)
		goto err;

	if (task->sysvsem.undo_list_id != UNIQUE_ID_NONE) {
		r = add_to_shared_objects_list(task->application, SEMUNDO_LIST,
					       key, 0 /* !is_local */, task,
					       NULL);

		if (r == -ENOKEY) /* the semundo list was already in the list */
			r = 0;
	}
err:
	return r;
}

int export_sysv_sem(struct epm_action *action,
		    ghost_t *ghost, struct task_struct *task)
{
	int r;
	unique_id_t undo_list_id = UNIQUE_ID_NONE;

	BUG_ON(task->sysvsem.undo_list);

	if (action->type == EPM_CHECKPOINT &&
	    action->checkpoint.shared == CR_SAVE_LATER) {
		r = cr_export_later_sysv_sem(action, ghost, task);
		return r;
	}

	/* lazy creation of semundo list:
	   - nothing to do on migration
	   - nothing to do on remote fork if CLONE_SYSVSEM is not set
	   - need to create it if CLONE_SYSVSEM and still not created */
	if (task->sysvsem.undo_list_id == UNIQUE_ID_NONE
	    && action->type == EPM_REMOTE_CLONE
	    && (action->remote_clone.clone_flags & CLONE_SYSVSEM)) {
		r = create_semundo_proc_list(task);
		if (r)
			goto err;

		undo_list_id = UNIQUE_ID_NONE;
	}

	/* does the remote process will use our undo_list ? */
	if (action->type == EPM_MIGRATE
	    || action->type == EPM_CHECKPOINT
	    || (action->type == EPM_REMOTE_CLONE
		&& (action->remote_clone.clone_flags & CLONE_SYSVSEM)))
		undo_list_id = task->sysvsem.undo_list_id;

	r = ghost_write(ghost, &undo_list_id, sizeof(unique_id_t));

err:
	return r;
}

static int cr_link_to_sysv_sem(struct epm_action *action,
			       ghost_t *ghost,
			       struct task_struct *task)
{
	int r;
	long key;
	unique_id_t undo_list_id;

	r = ghost_read(ghost, &key, sizeof(long));
	if (r)
		goto err;

	if ((unique_id_t)key == UNIQUE_ID_NONE) {
		task->sysvsem.undo_list_id = UNIQUE_ID_NONE;
	} else {
		undo_list_id = (unique_id_t)get_imported_shared_object(
			action->restart.app,
			SEMUNDO_LIST, key);

		BUG_ON(undo_list_id == UNIQUE_ID_NONE);
		r = share_existing_semundo_proc_list(task, undo_list_id);
	}
err:
	return r;
}

int import_sysv_sem(struct epm_action *action,
		    ghost_t *ghost, struct task_struct *task)
{
	int r;
	unique_id_t undo_list_id;

	task->sysvsem.undo_list = NULL; /* fake task_struct ... */

	if (action->type == EPM_CHECKPOINT
	    && action->restart.shared == CR_LINK_ONLY) {
		r = cr_link_to_sysv_sem(action, ghost, task);
		return r;
	}

	task->sysvsem.undo_list_id = UNIQUE_ID_NONE;
	/*BUG_ON(task->sysvsem.undo_list);*/

	r = ghost_read(ghost, &undo_list_id, sizeof(unique_id_t));
	if (r)
		goto err;

	if (undo_list_id != UNIQUE_ID_NONE) {
		if (action->type == EPM_CHECKPOINT)
			r = create_semundo_proc_list(task);
		else
			r = share_existing_semundo_proc_list(task,
							     undo_list_id);
	}

err:
	return r;
}

void unimport_sysv_sem(struct task_struct *task)
{
	task->sysvsem.undo_list_id = UNIQUE_ID_NONE;
}

static int cr_export_now_sysv_sem(struct epm_action *action, ghost_t *ghost,
				  struct task_struct *task,
				  union export_args *args)
{
	int r;
	r = export_sysv_sem(action, ghost, task);
	return r;
}


static int cr_import_now_sysv_sem(struct epm_action *action, ghost_t *ghost,
				  struct task_struct *fake, int local_only,
				  void ** returned_data, size_t *data_size)
{
	int r;
	BUG_ON(*returned_data != NULL);

	r = import_sysv_sem(action, ghost, fake);
	if (r)
		goto err;

	*returned_data = (void*)fake->sysvsem.undo_list_id;
err:
	return r;
}

static int cr_import_complete_sysv_sem(struct task_struct * fake,
				       void * _undo_list_id)
{
	unique_id_t undo_list_id = (unique_id_t)_undo_list_id;

	fake->sysvsem.undo_list_id = undo_list_id;

	exit_sem(fake);

	return 0;
}

static int cr_delete_sysv_sem(struct task_struct * fake, void * _undo_list_id)
{
	unique_id_t undo_list_id = (unique_id_t)_undo_list_id;

	destroy_semundo_proc_list(fake, undo_list_id);

	return 0;
}


struct shared_object_operations cr_shared_semundo_ops = {
        .export_now        = cr_export_now_sysv_sem,
	.import_now        = cr_import_now_sysv_sem,
	.import_complete   = cr_import_complete_sysv_sem,
	.delete            = cr_delete_sysv_sem,
};

/******************************************************************************/

/* mostly copy/paste from store_msg */
static int export_full_one_msg(ghost_t *ghost, struct msg_msg *msg)
{
	int r = 0;

	int alen;
	int len;
	struct msg_msgseg *seg;

	r = ghost_write(ghost, &msg->m_ts, sizeof(int));
	if (r)
		goto out;

	r = ghost_write(ghost, msg, sizeof(struct msg_msg));
	if (r)
		goto out;

	len = msg->m_ts;
	alen = len;
	if (alen > DATALEN_MSG)
		alen = DATALEN_MSG;

	r = ghost_write(ghost, msg + 1, alen);
	if (r)
		goto out;

	len -= alen;
	seg = msg->next;
	while (len > 0) {
		alen = len;
		if (alen > DATALEN_SEG)
			alen = DATALEN_SEG;

		r = ghost_write(ghost, seg + 1, alen);
		if (r)
			goto out;

		len -= alen;
		seg = seg->next;
	}
out:
	return r;
}

static int export_full_all_msgs(ghost_t * ghost, struct msg_queue *msq)
{
	int r = 0;
	struct msg_msg *msg;

	r = ghost_write(ghost, &msq->q_qnum, sizeof(unsigned long));
	if (r)
		goto out;

	list_for_each_entry(msg, &msq->q_messages, m_list) {
		r = export_full_one_msg(ghost, msg);
		if (r)
			goto out;
	}
out:
	return r;
}

int export_full_sysv_msgq(ghost_t *ghost, int msgid)
{
	int r = 0;
	struct msg_queue *msq;
	struct ipc_namespace *ns;

	ns = find_get_krg_ipcns();
	if (!ns)
		return -ENOSYS;

	msq = msg_lock(ns, msgid);
	if (IS_ERR(msq)) {
		r = PTR_ERR(msq);
		goto out;
	}

	if (!msq->is_master) {
		r = -EPERM;
		goto out_unlock;
	}

	r = ghost_write(ghost, msq, sizeof(struct msg_queue));
	if (r)
		goto out_unlock;

	r = export_full_all_msgs(ghost, msq);

out_unlock:
	msg_unlock(msq);
out:
	put_ipc_ns(ns);
	return r;
}

/* mostly copy/paste from load_msg */
static struct msg_msg *import_full_one_msg(ghost_t * ghost)
{
	struct msg_msg *msg = NULL;
	struct msg_msgseg **pseg;
	int r;
	int len, alen;

	r = ghost_read(ghost, &len, sizeof(int));
	if (r)
		goto out_err;

	alen = len;
	if (alen > DATALEN_MSG)
		alen = DATALEN_MSG;

	msg = kmalloc(sizeof(*msg) + alen, GFP_KERNEL);
	if (msg == NULL)
		return ERR_PTR(-ENOMEM);

	r = ghost_read(ghost, msg, sizeof(struct msg_msg));
	if (r)
		goto out_err;

	r = ghost_read(ghost, msg + 1, alen);
	if (r)
		goto out_err;

	msg->next = NULL;
	msg->security = NULL;

	len -= alen;
	pseg = &msg->next;
	while (len > 0) {
		struct msg_msgseg *seg;
		alen = len;
		if (alen > DATALEN_SEG)
			alen = DATALEN_SEG;

		seg = kmalloc(sizeof(*seg) + alen, GFP_KERNEL);

		if (!seg) {
			r = -ENOMEM;
			goto out_err;
		}
		*pseg = seg;
		seg->next = NULL;

		r = ghost_read(ghost, seg + 1, alen);
		if (r)
			goto out_err;

		pseg = &seg->next;
		len -= alen;
	}

	r = security_msg_msg_alloc(msg);
	if (r)
		goto out_err;

	return msg;

out_err:
	free_msg(msg);
	return ERR_PTR(r);
}

static int import_full_all_msgs(ghost_t *ghost, struct ipc_namespace *ns,
				struct msg_queue *msq)
{
	int i;
	int r = 0;
	unsigned long nbmsg;

	r = ghost_read(ghost, &nbmsg, sizeof(unsigned long));
	if (r)
		goto out;

	for (i = 0; i < nbmsg; i++) {
		struct msg_msg * msg = import_full_one_msg(ghost);
		if (IS_ERR(msg)) {
			r = PTR_ERR(msg);
			goto out;
		}
		list_add_tail(&msg->m_list, &msq->q_messages);
		atomic_inc(&ns->msg_hdrs);
		atomic_add(msg->m_ts, &ns->msg_bytes);
		msq->q_qnum++;
		msq->q_cbytes += msg->m_ts;
	}

out:
	return r;
}

int import_full_sysv_msgq(ghost_t *ghost)
{
	int r;
	struct ipc_namespace *ns;
	struct msg_queue copy_msq, *msq;
	struct ipc_params params;

	r = ghost_read(ghost, &copy_msq, sizeof(struct msg_queue));
	if (r)
		goto out;

	ns = find_get_krg_ipcns();
	if (!ns)
		return -ENOSYS;

	down_write(&msg_ids(ns).rw_mutex);

	params.requested_id = copy_msq.q_perm.id;
	params.key = copy_msq.q_perm.key;
	params.flg = copy_msq.q_perm.mode;

	r = newque(ns, &params);
	if (r < 0)
		goto out_put_ns;

	BUG_ON(r != params.requested_id);

	/* the message queue cannot disappear since we hold the ns mutex */
	msq = msg_lock(ns, params.requested_id);
	if (IS_ERR(msq)) {
		r = PTR_ERR(msq);
		goto out_put_ns;
	}

	r = import_full_all_msgs(ghost, ns, msq);
	if (r)
		goto out_freeque;

	msq->q_stime = copy_msq.q_stime;
	msq->q_rtime = copy_msq.q_rtime;
	msq->q_ctime = copy_msq.q_ctime;

	msq->q_lspid = copy_msq.q_lspid;
	msq->q_lrpid = copy_msq.q_lrpid;

	msg_unlock(msq);
out_put_ns:
	up_write(&msg_ids(ns).rw_mutex);

	put_ipc_ns(ns);
out:
	return r;

out_freeque:
	kh_ipc_msg_freeque(ns, &msq->q_perm);
	goto out_put_ns;
}

/******************************************************************************/

int export_full_sysv_sem(ghost_t *ghost, int semid)
{
	int r;
	struct ipc_namespace *ns;
	struct sem_array *sma;

	ns = find_get_krg_ipcns();
	if (!ns)
		return -ENOSYS;

	sma = sem_lock(ns, semid);
	if (IS_ERR(sma)) {
		r = PTR_ERR(sma);
		goto out;
	}

	r = ghost_write(ghost, sma, sizeof(struct sem_array));
	if (r)
		goto out;

	r = ghost_write(ghost, sma->sem_base, sma->sem_nsems * sizeof(struct sem));
	if (r)
		goto out;

	sem_unlock(sma);

out:
	put_ipc_ns(ns);
	return r;
}

int import_full_sysv_sem(ghost_t *ghost)
{
	int r;
	struct ipc_namespace *ns;
	struct sem_array copy_sma, *sma;
	struct ipc_params params;

	r = ghost_read(ghost, &copy_sma, sizeof(struct sem_array));
	if (r)
		goto out;

	ns = find_get_krg_ipcns();
	if (!ns)
		return -ENOSYS;

	down_write(&sem_ids(ns).rw_mutex);

	params.requested_id = copy_sma.sem_perm.id;
	params.key = copy_sma.sem_perm.key;
	params.flg = copy_sma.sem_perm.mode;
	params.u.nsems = copy_sma.sem_nsems;

	r = newary(ns, &params);
	if (r < 0)
		goto out_put_ns;

	BUG_ON(r != params.requested_id);

	/* the semaphore array cannot disappear since we hold the ns mutex */
	sma = sem_lock(ns, params.requested_id);
	if (IS_ERR(sma)) {
		r = PTR_ERR(sma);
		goto out_put_ns;
	}

	r = ghost_read(ghost, sma->sem_base, sma->sem_nsems * sizeof(struct sem));
	if (r)
		goto out_freeary;

	sma->sem_otime = copy_sma.sem_otime;
	sma->sem_ctime = copy_sma.sem_ctime;

	sem_unlock(sma);

out_put_ns:
	up_write(&sem_ids(ns).rw_mutex);

	put_ipc_ns(ns);
out:
	return r;

out_freeary:
	kh_ipc_sem_freeary(ns, &sma->sem_perm);
	goto out_put_ns;
}
