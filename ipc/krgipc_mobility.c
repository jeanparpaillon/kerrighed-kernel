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
#include <linux/hugetlb.h>
#include <linux/msg.h>
#include <linux/security.h>
#include <linux/sem.h>
#include <linux/shm.h>
#include <linux/syscalls.h>
#include <linux/unique_id.h>
#include <net/krgrpc/rpc.h>
#include <net/krgrpc/rpcid.h>
#include <kddm/kddm.h>
#include <kerrighed/namespace.h>
#include <kerrighed/ghost.h>
#include <kerrighed/ghost_helpers.h>
#include <kerrighed/action.h>
#include <kerrighed/application.h>
#include <kerrighed/app_shared.h>
#include <kerrighed/faf.h>
#include <kerrighed/faf_file_mgr.h>
#include <kerrighed/file.h>
#include <kerrighed/regular_file_mgr.h>
#include <kerrighed/pid.h>
#include "ipc_handler.h"
#include "krgipc_mobility.h"
#include "krgshm.h"
#include "krgmsg.h"
#include "krgsem.h"
#include "msg_handler.h"
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
	struct regular_file_krg_desc *data;
	int size, r = -ENOENT;

	size = sizeof(struct regular_file_krg_desc);

	data = kmalloc (size, GFP_KERNEL);
	if (!data) {
		r = -ENOMEM;
		goto exit;
	}

	data->type = SHM;
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
	struct regular_file_krg_desc *desc = _desc;
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
	if (task->nsproxy->ipc_ns != task->nsproxy->krg_ns->root_nsproxy.ipc_ns)
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


static int cr_export_semundos(ghost_t *ghost, struct task_struct *task)
{
	int r = 0;
	struct semundo_list_object *undo_list;
	struct kddm_set *undo_list_kddm_set;
	struct semundo_id *undo_id;
	long nb_semundo;

	if (task->sysvsem.undo_list_id == UNIQUE_ID_NONE)
		goto exit;

	undo_list_kddm_set = task_undolist_set(task);
	if (IS_ERR(undo_list_kddm_set)) {
		r = PTR_ERR(undo_list_kddm_set);
		goto exit;
	}

	/* get the list of semaphores for which we have a semundo */
	undo_list = _kddm_grab_object_no_ft(undo_list_kddm_set,
					    task->sysvsem.undo_list_id);
	if (!undo_list) {
		r = -ENOMEM;
		goto exit_put;
	}

	nb_semundo = 0;
	for (undo_id = undo_list->list; undo_id; undo_id = undo_id->next)
		nb_semundo++;

	r = ghost_write(ghost, &nb_semundo, sizeof(long));
	if (r)
		goto exit_put;

	for (undo_id = undo_list->list; undo_id; undo_id = undo_id->next) {

		struct ipc_namespace *ns = task_nsproxy(task)->ipc_ns;
		struct sem_undo *undo;
		struct sem_array *sma = sem_lock(ns, undo_id->semid);

		if (IS_ERR(sma)) {
			BUG();
			r = PTR_ERR(sma);
			goto exit_put;
		}

		list_for_each_entry(undo, &sma->list_id, list_id) {
			if (undo->proc_list_id == task->sysvsem.undo_list_id) {
				int size;

				r = ghost_write(ghost,
						&sma->sem_perm.id, sizeof(int));
				if (r)
					goto exit_put;

				size = sizeof(struct sem_undo) +
					sma->sem_nsems * sizeof(short);
				r = ghost_write(ghost, &size, sizeof(int));
				if (r)
					goto exit_put;

				r = ghost_write(ghost, undo, size);
				if (r)
					goto exit_put;

				goto next_sma;
			}
		}
		BUG();
	next_sma:
		sem_unlock(sma);
	}

exit_put:
	 _kddm_put_object(undo_list_kddm_set, task->sysvsem.undo_list_id);
exit:
	return r;
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
					       key, SHARED_ANY, task,
					       NULL, 0);

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

	if (task->exit_state)
		return 0;

	BUG_ON(task->sysvsem.undo_list);
	BUG_ON(action->type == EPM_RESTART);

	if (action->type == EPM_CHECKPOINT) {
		BUG_ON(action->checkpoint.shared != CR_SAVE_LATER);
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
	}

	/* does the remote process will use our undo_list ? */
	if (action->type == EPM_MIGRATE
	    || (action->type == EPM_REMOTE_CLONE
		&& (action->remote_clone.clone_flags & CLONE_SYSVSEM)))
		undo_list_id = task->sysvsem.undo_list_id;

	r = ghost_write(ghost, &undo_list_id, sizeof(unique_id_t));

err:
	return r;
}

static int cr_import_one_semundo(ghost_t *ghost, struct task_struct *task,
				 struct semundo_list_object *undo_list)
{
	int size, semid, r = 0;
	struct sem_array *sma;
	struct sem_undo *undo;

	struct ipc_namespace *ns = task_nsproxy(task)->ipc_ns;

	r = ghost_read(ghost, &semid, sizeof(int));
	if (r)
		goto end;

	sma = sem_lock_check(ns, semid);
	if (IS_ERR(sma)) {
		r = PTR_ERR(sma);
		goto end;
	}

	r = ghost_read(ghost, &size, sizeof(int));
	if (r)
		goto unlock_sma;

	if (size != sizeof(struct sem_undo) + sma->sem_nsems * sizeof(short)) {
		printk("This is not the good semaphore... no way to restart\n");
		r = -EFAULT;
		goto unlock_sma;
	}

	undo = kzalloc(size, GFP_KERNEL);
	if (!undo)
		goto unlock_sma;

	r = ghost_read(ghost, undo, size);
	if (r)
		goto free_undo;

	INIT_LIST_HEAD(&undo->list_proc); /* list_proc is useless!*/
	undo->proc_list_id = undo_list->id; /* id may have changed */
	undo->semadj = (short *) &undo[1];

	r = add_semundo_to_proc_list(undo_list, sma->sem_perm.id);
	if (r)
		goto free_undo;

	list_add(&undo->list_id, &sma->list_id);

unlock_sma:
	sem_unlock(sma);
end:
	return r;

free_undo:
	kfree(undo);
	goto unlock_sma;
}

static int cr_import_semundos(ghost_t *ghost, struct task_struct *task)
{
	int r = 0;
	struct kddm_set *undo_list_set;
	struct semundo_list_object *undo_list;
	long i, nb_semundo;

	if (task->sysvsem.undo_list_id == UNIQUE_ID_NONE)
		goto err;

	undo_list_set = task_undolist_set(task);
	if (IS_ERR(undo_list_set)) {
		r = PTR_ERR(undo_list_set);
		goto err;
	}

	/* get the list of semaphores for which we have a semundo */
	undo_list = _kddm_grab_object_no_ft(undo_list_set,
					    task->sysvsem.undo_list_id);
	if (!undo_list) {
		r = -ENOMEM;
		goto exit_put;
	}

	r = ghost_read(ghost, &nb_semundo, sizeof(long));
	if (r || !nb_semundo)
		goto exit_put;

	for (i = 0; i < nb_semundo; i++) {
		r = cr_import_one_semundo(ghost, task, undo_list);
		if (r)
			goto unimport_semundos;
	}

exit_put:
	_kddm_put_object(undo_list_set, task->sysvsem.undo_list_id);
err:
	return r;

unimport_semundos:
	_kddm_remove_frozen_object(undo_list_set, task->sysvsem.undo_list_id);
	goto err;
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

	BUG_ON(action->type == EPM_CHECKPOINT);

	if (task->exit_state)
		return 0;

	if (action->type == EPM_RESTART) {
		BUG_ON(action->restart.shared != CR_LINK_ONLY);
		r = cr_link_to_sysv_sem(action, ghost, task);
		return r;
	}

	task->sysvsem.undo_list_id = UNIQUE_ID_NONE;
	/*BUG_ON(task->sysvsem.undo_list);*/

	r = ghost_read(ghost, &undo_list_id, sizeof(unique_id_t));
	if (r)
		goto err;

	if (undo_list_id == UNIQUE_ID_NONE)
		goto err;

	r = share_existing_semundo_proc_list(task, undo_list_id);

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

	unique_id_t undo_list_id = task->sysvsem.undo_list_id;

	r = ghost_write(ghost, &undo_list_id, sizeof(unique_id_t));
	if (r)
		goto err;

	r = cr_export_semundos(ghost, task);
err:
	if (r)
		epm_error(action, r, task,
			  "Fail to save semundos");

	return r;
}


static int cr_import_now_sysv_sem(struct epm_action *action, ghost_t *ghost,
				  struct task_struct *fake, int local_only,
				  void ** returned_data, size_t *data_size)
{
	int r;
	unique_id_t undo_list_id;

	BUG_ON(*returned_data != NULL);

	r = ghost_read(ghost, &undo_list_id, sizeof(unique_id_t));
	if (r)
		goto err;

	if (undo_list_id == UNIQUE_ID_NONE)
		goto err;

	fake->sysvsem.undo_list = NULL; /* fake task_struct ... */
	fake->sysvsem.undo_list_id = UNIQUE_ID_NONE;

	r = create_semundo_proc_list(fake);
	if (r)
		goto err;

	r = cr_import_semundos(ghost, fake);
	if (r)
		goto err;

	*returned_data = (void*)fake->sysvsem.undo_list_id;
err:
	if (r)
		epm_error(action, r, fake,
			  "Fail to restore semundos");
	return r;
}

static int cr_import_complete_sysv_sem(struct task_struct * fake,
				       void * _undo_list_id)
{
	unique_id_t undo_list_id = (unique_id_t)_undo_list_id;

	fake->sysvsem.undo_list = NULL;
	fake->sysvsem.undo_list_id = undo_list_id;

	exit_sem(fake);

	return 0;
}

static int cr_delete_sysv_sem(struct task_struct * fake, void * _undo_list_id)
{
	unique_id_t undo_list_id = (unique_id_t)_undo_list_id;

	fake->sysvsem.undo_list = NULL;
	fake->sysvsem.undo_list_id = undo_list_id;

	exit_sem(fake);

	return 0;
}

struct shared_object_operations cr_shared_semundo_ops = {
        .export_now        = cr_export_now_sysv_sem,
	.export_user_info  = NULL,
	.import_now        = cr_import_now_sysv_sem,
	.import_complete   = cr_import_complete_sysv_sem,
	.delete            = cr_delete_sysv_sem,
};

/******************************************************************************/

static const int CR_MSG_MAGIC = 0x33333311;

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

int export_full_all_msgs(ghost_t * ghost, struct msg_queue *msq)
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

static int export_full_local_sysv_msgq(ghost_t *ghost, int msgid)
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

	if (msq->master_node != kerrighed_node_id) {
		r = -EPERM;
		goto out_unlock;
	}

	r = ghost_write(ghost, &CR_MSG_MAGIC, sizeof(int));
	if (r)
		goto out_unlock;

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

static int local_sys_msgq_checkpoint(int msqid, int fd)
{
	int r;
	ghost_fs_t oldfs;
	ghost_t *ghost;

	__set_ghost_fs(&oldfs);

	ghost = create_file_ghost_from_fd(GHOST_WRITE, fd);

	if (IS_ERR(ghost)) {
		r = PTR_ERR(ghost);
		goto exit;
	}

	r = export_full_local_sysv_msgq(ghost, msqid);

	ghost_close(ghost);
exit:
	unset_ghost_fs(&oldfs);
	return r;
}

struct msgq_checkpoint_msg
{
	int msqid;
};

void handle_msg_checkpoint(struct rpc_desc *desc, void *_msg, size_t size)
{
	int r, fd;
	struct msgq_checkpoint_msg *msg = _msg;

	fd = receive_fd_from_network(desc);
	if (fd < 0) {
		r = fd;
		goto error;
	}

	r = __sys_msgq_checkpoint(msg->msqid, fd);

	sys_close (fd);

error:
	r = rpc_pack_type(desc, r);
	if (r)
		rpc_cancel(desc);
}

int __sys_msgq_checkpoint(int msqid, int fd)
{
	int r, index, err;
	struct msgq_checkpoint_msg msg;
	struct kddm_set *master_set;
	kerrighed_node_t *master_node;
	struct ipc_namespace *ns;
	struct file *file;
	struct rpc_desc *desc;

	ns = find_get_krg_ipcns();

	index = ipcid_to_idx(msqid);

	master_set = krgipc_ops_master_set(msg_ids(ns).krgops);

	master_node = _kddm_get_object_no_ft(master_set, index);
	if (!master_node) {
		_kddm_put_object(master_set, index);
		r = -EINVAL;
		goto out;
	}

	if (*master_node == kerrighed_node_id) {
		_kddm_put_object(master_set, index);
		r = local_sys_msgq_checkpoint(msqid, fd);
		goto out;
	}

	file = fget(fd);

	desc = rpc_begin(IPC_MSG_CHKPT, master_set->ns->rpc_comm, *master_node);
	_kddm_put_object(master_set, index);

	msg.msqid = msqid;
	r = rpc_pack_type(desc, msg);
	if (r)
		goto err_rpc;

	r = send_faf_file_desc(desc, file);
	if (r)
		goto err_rpc;

	r = rpc_unpack_type(desc, err);
	if (r)
		goto err_rpc;

	r = err;

out_put_file:
	fput(file);
out:
	put_ipc_ns(ns);
	return r;

err_rpc:
	rpc_cancel(desc);
	goto out_put_file;
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

int import_full_all_msgs(ghost_t *ghost, struct ipc_namespace *ns,
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
	int r, magic;
	struct ipc_namespace *ns;
	struct msg_queue copy_msq, *msq;
	struct ipc_params params;

	r = ghost_read(ghost, &magic, sizeof(int));
	if (r)
		goto out;

	if (magic != CR_MSG_MAGIC) {
		r = -EINVAL;
		goto out;
	}

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
	krg_ipc_msg_freeque(ns, &msq->q_perm);
	goto out_put_ns;
}

/******************************************************************************/

static const int CR_SEM_MAGIC = 0x33333322;

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

	r = ghost_write(ghost, &CR_SEM_MAGIC, sizeof(int));
	if (r)
		goto out;

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
	int r, magic;
	struct ipc_namespace *ns;
	struct sem_array copy_sma, *sma;
	struct ipc_params params;

	r = ghost_read(ghost, &magic, sizeof(int));
	if (r)
		goto out;

	if (magic != CR_SEM_MAGIC) {
		r = -EINVAL;
		goto out;
	}

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
	krg_ipc_sem_freeary(ns, &sma->sem_perm);
	goto out_put_ns;
}

/******************************************************************************/

static const int CR_SHM_MAGIC = 0x33333333;

static int export_full_one_shm_page(ghost_t * ghost, struct kddm_set *kset,
				    unsigned long pageid, unsigned long size)
{
	int r;
	struct page *page;
	char *data;
	const int no_page=0, page_used = 1;

	page = _kddm_get_object_no_ft(kset, (objid_t)pageid);
	if (page) {
		r = ghost_write(ghost, &page_used, sizeof(int));
		if (r)
			goto put_page;
		data = (char *)kmap(page);
		r = ghost_write(ghost, data, size);
		kunmap(page);
	} else
		r = ghost_write(ghost, &no_page, sizeof(int));

put_page:
	_kddm_put_object(kset, (objid_t)pageid);
	return r;
}

/* shp must be locked */
static int export_full_shm_content(ghost_t * ghost, struct ipc_namespace *ns,
				   struct shmid_kernel **shp)
{
	int r = 0;
	int shmid;
	struct kddm_set *kset;
	unsigned long i;
	unsigned long nb_pages;
	unsigned long left_size;

	shmid = (*shp)->shm_perm.id;

	nb_pages = (*shp)->shm_segsz / PAGE_SIZE;
	left_size = (*shp)->shm_segsz % PAGE_SIZE;

	kset = (*shp)->shm_file->f_dentry->d_inode->i_mapping->kddm_set;

	/* to ensure the SHP will stay alive without deadlocking
	 * with the IO Linker...
	 */
	(*shp)->shm_nattch++;
	shm_unlock(*shp);

	for (i = 0; i < nb_pages && r == 0; i++)
		r = export_full_one_shm_page(ghost, kset, i, PAGE_SIZE);

	if (r)
		goto error;

	if (left_size)
		r = export_full_one_shm_page(ghost, kset, i, left_size);

error:
	*shp = shm_lock(ns, shmid);
	BUG_ON(IS_ERR(*shp));
	(*shp)->shm_nattch--;

	return r;
}

int export_full_sysv_shm(ghost_t *ghost, int shmid)
{
	int r, flag;
	struct ipc_namespace *ns;
	struct shmid_kernel *shp;

	ns = find_get_krg_ipcns();
	if (!ns)
		return -ENOSYS;

	shp = shm_lock(ns, shmid);
	if (IS_ERR(shp)) {
		r = PTR_ERR(shp);
		goto out;
	}

	r = ghost_write(ghost, &CR_SHM_MAGIC, sizeof(int));
	if (r)
		goto out_shm_unlock;

	r = ghost_write(ghost, shp, sizeof(struct shmid_kernel));
	if (r)
		goto out_shm_unlock;

	flag = shp->shm_perm.mode;
#ifdef CONFIG_HUGETLB_PAGE
	if (shp->shm_file->f_op == &hugetlbfs_file_operations)
		flag |= SHM_HUGETLB;
#endif
	/* SHM_NORESERVE not handled */

	r = ghost_write(ghost, &flag, sizeof(int));
	if (r)
		goto out_shm_unlock;

	r = export_full_shm_content(ghost, ns, &shp);

out_shm_unlock:
	shm_unlock(shp);
out:
	put_ipc_ns(ns);
	return r;
}

static int import_full_one_shm_page(ghost_t * ghost, struct kddm_set *kset,
				    unsigned long pageid,
				    unsigned long size)
{
	int r;
	struct page *page;
	char* data;
	int page_used;

	r = ghost_read(ghost, &page_used, sizeof(page_used));
	if (r)
		goto out;

	if (!page_used)
		goto out;

	/* it should return an existing but empty object */
	page = _kddm_grab_object(kset, (objid_t)pageid);
	if (!page)
		goto put_page;

	data = (char *)kmap(page);
	r = ghost_read(ghost, data, size);
	kunmap(page);

put_page:
	_kddm_put_object(kset, (objid_t)pageid);
out:
	return r;
}

/* shp must be locked */
static int import_full_shm_content(ghost_t * ghost, struct ipc_namespace *ns,
				   struct shmid_kernel **shp)
{
	int r = 0;
	int shmid;
	struct kddm_set *kset;
	unsigned long nb_pages;
	unsigned long left_size;
	unsigned long i;

	shmid = (*shp)->shm_perm.id;

	nb_pages = (*shp)->shm_segsz / PAGE_SIZE;
	left_size = (*shp)->shm_segsz % PAGE_SIZE;

	kset = (*shp)->shm_file->f_dentry->d_inode->i_mapping->kddm_set;

	/* to ensure the SHP will stay alive without deadlocking
	 * with the IO Linker...
	 */
	(*shp)->shm_nattch++;
	shm_unlock(*shp);

	for (i = 0; i < nb_pages && r == 0; i++)
		r = import_full_one_shm_page(ghost, kset, i, PAGE_SIZE);

	if (r)
		goto error;

	if (left_size)
		r = import_full_one_shm_page(ghost, kset, i, left_size);

error:
	*shp = shm_lock(ns, shmid);
	BUG_ON(IS_ERR(*shp));
	(*shp)->shm_nattch--;

	return r;
}

int import_full_sysv_shm(ghost_t *ghost)
{
	int r, flag, magic;
	struct ipc_namespace *ns;
	struct shmid_kernel copy_shp, *shp;
	struct ipc_params params;

	r = ghost_read(ghost, &magic, sizeof(int));
	if (r)
		goto out;

	if (magic != CR_SHM_MAGIC) {
		r = -EINVAL;
		goto out;
	}

	r = ghost_read(ghost, &copy_shp, sizeof(struct shmid_kernel));
	if (r)
		goto out;

	r = ghost_read(ghost, &flag, sizeof(int));
	if (r)
		goto out;

	ns = find_get_krg_ipcns();
	if (!ns)
		return -ENOSYS;

	down_write(&shm_ids(ns).rw_mutex);

	params.requested_id = copy_shp.shm_perm.id;
	params.key = copy_shp.shm_perm.key;
	params.flg = flag;
	params.u.size = copy_shp.shm_segsz;

	r = newseg(ns, &params);
	if (r < 0)
		goto out_put_ns;

	BUG_ON(r != params.requested_id);

	/* the memory segment cannot disappear since we hold the ns mutex */
	shp = shm_lock(ns, params.requested_id);
	if (IS_ERR(shp)) {
		r = PTR_ERR(shp);
		goto out_put_ns;
	}

	r = import_full_shm_content(ghost, ns, &shp);
	if (r)
		goto out_freeshm;

	shp->shm_atim = copy_shp.shm_atim;
	shp->shm_dtim = copy_shp.shm_dtim;
	shp->shm_ctim = copy_shp.shm_ctim;
	shp->shm_cprid = copy_shp.shm_cprid;
	shp->shm_lprid = copy_shp.shm_lprid;

	shm_unlock(shp);

out_put_ns:
	up_write(&shm_ids(ns).rw_mutex);

	put_ipc_ns(ns);
out:
	return r;
out_freeshm:
	BUG_ON(shp->shm_nattch);
	krg_ipc_shm_destroy(ns, shp);
	goto out;
}


