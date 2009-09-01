/*
 *  kerrighed/epm/app_checkpoint.c
 *
 *  Copyright (C) 1999-2006 INRIA, Universite de Rennes 1, EDF
 *  Copyright (C) 2007-2008 Matthieu Fertré - INRIA
 */

#include <linux/compile.h>
#include <linux/pid_namespace.h>
#include <linux/cred.h>
#include <linux/syscalls.h>
#include <linux/version.h>
#include <kerrighed/pid.h>
#include <kerrighed/task.h>
#include <kerrighed/children.h>
#include <kerrighed/kerrighed_signal.h>
#include <kerrighed/action.h>
#include <kerrighed/application.h>
#include <kerrighed/app_shared.h>
#include <kerrighed/app_terminal.h>
#include <kerrighed/sys/checkpoint.h>
#include <kerrighed/ghost.h>
#include <kerrighed/remote_cred.h>
#include <kerrighed/physical_fs.h>
#include <net/krgrpc/rpcid.h>
#include <net/krgrpc/rpc.h>
#include <kddm/kddm.h>
#include "app_frontier.h"
#include "app_utils.h"
#include "../checkpoint.h"
#include "../epm_internal.h"

/*--------------------------------------------------------------------------*/

static inline int save_app_kddm_object(struct app_kddm_object *obj,
				       int one_terminal)
{
	ghost_fs_t oldfs;
	ghost_t *ghost;
	int magic = 4342338;
	int r = 0;
	u32 linux_version;

	__set_ghost_fs(&oldfs);

	ghost = create_file_ghost(GHOST_WRITE, obj->app_id, obj->chkpt_sn,
				  -1, "global");

	if (IS_ERR(ghost)) {
		r = PTR_ERR(ghost);
		goto exit;
	}

	/* write information about the Linux kernel version */
	linux_version = LINUX_VERSION_CODE;
	r = ghost_write(ghost, &linux_version, sizeof(linux_version));
	if (r)
		goto err_write;
	r = ghost_write_string(ghost, UTS_MACHINE);
	if (r)
		goto err_write;
	r = ghost_write_string(ghost, UTS_VERSION);
	if (r)
		goto err_write;
	r = ghost_write_string(ghost, LINUX_COMPILE_TIME);
	if (r)
		goto err_write;
	r = ghost_write_string(ghost, LINUX_COMPILE_BY);
	if (r)
		goto err_write;
	r = ghost_write_string(ghost, LINUX_COMPILE_HOST);
	if (r)
		goto err_write;
	r = ghost_write_string(ghost, LINUX_COMPILER);
	if (r)
		goto err_write;

	/* write information about the checkpoint itself */
	r = ghost_write(ghost, &obj->app_id, sizeof(obj->app_id));
	if (r)
		goto err_write;
	r = ghost_write(ghost, &obj->chkpt_sn, sizeof(obj->chkpt_sn));
	if (r)
		goto err_write;
	r = ghost_write(ghost, &obj->nodes, sizeof(obj->nodes));
	if (r)
		goto err_write;
	r = ghost_write(ghost, &obj->user_data, sizeof(obj->user_data));
	if (r)
		goto err_write;
	r = ghost_write(ghost, &one_terminal, sizeof(one_terminal));
	if (r)
		goto err_write;
	r = ghost_write(ghost, &magic, sizeof(magic));
	if (r)
		goto err_write;

err_write:
	/* End of the really interesting part */
	ghost_close(ghost);

exit:
	unset_ghost_fs(&oldfs);

	return r;
}

static inline int write_task_parent_links(task_state_t *t,
					  ghost_t *ghost)
{
	int r = 0;
	pid_t parent, real_parent, real_parent_tgid;
	pid_t pid, tgid, pgrp, session;
	struct children_kddm_object *obj;

	if (!can_be_checkpointed(t->task)) {
		r = -EPERM;
		goto error;
	}

	pid = task_pid_knr(t->task);
	r = ghost_write(ghost, &pid, sizeof(pid_t));
	if (r)
		goto error;

	tgid = task_tgid_knr(t->task);
	r = ghost_write(ghost, &tgid, sizeof(pid_t));
	if (r)
		goto error;

	obj = krg_parent_children_readlock(t->task, &real_parent_tgid);
	if (obj) {
		r = krg_get_parent(obj, t->task, &parent, &real_parent);
		BUG_ON(r);
		krg_children_unlock(obj);
	} else {
		struct task_struct *reaper =
			task_active_pid_ns(t->task)->child_reaper;
		parent = real_parent = task_pid_knr(reaper);
		real_parent_tgid = parent;
	}

	r = ghost_write(ghost, &parent, sizeof(pid_t));
	if (r)
		goto error;
	r = ghost_write(ghost, &real_parent, sizeof(pid_t));
	if (r)
		goto error;
	r = ghost_write(ghost, &real_parent_tgid, sizeof(pid_t));
	if (r)
		goto error;

	if (has_group_leader_pid(t->task)) {
		pgrp = task_pgrp_knr(t->task);
		r = ghost_write(ghost, &pgrp, sizeof(pid_t));
		if (r)
			goto error;

		session = task_session_knr(t->task);
		r = ghost_write(ghost, &session, sizeof(pid_t));
		if (r)
			goto error;
	}

error:
	return r;
}

/*
 * Store the _LOCAL_ checkpoint description in a file
 */
static inline int save_local_app(struct app_struct *app, int chkpt_sn)
{
	ghost_fs_t oldfs;
	ghost_t *ghost;
	int r = 0;
	int null = -1;
	task_state_t *t;
	struct list_head *tmp, *element;

	__set_ghost_fs(&oldfs);

	ghost = create_file_ghost(GHOST_WRITE, app->app_id, chkpt_sn,
				  kerrighed_node_id, "node");

	if (IS_ERR(ghost)) {
		r = PTR_ERR(ghost);
		goto exit;
	}

	/* Here is the really interesting part */
	r = ghost_write(ghost, &kerrighed_node_id, sizeof(kerrighed_node_t));
	if (r)
		goto err_write;

	/*
	 * write all the description of the local tasks involved in the
	 * checkpoint
	 * there is no need to lock the application list of processes because
	 * all application processes are already stopped
	 */
	list_for_each_safe(element, tmp, &app->tasks) {
		t = list_entry(element, task_state_t, next_task);
		r = write_task_parent_links(t, ghost);
		if (r)
			goto err_write;
	}

	/* end of file marker */
	r = ghost_write(ghost, &null, sizeof(int));
	if (r)
		goto err_write;
	r = ghost_write(ghost, &null, sizeof(int));
	if (r)
		goto err_write;
err_write:
	/* End of the really interesting part */
	ghost_close(ghost);

/*
 * WARNING: if no tasks are finally checkpointable, we should unregister
 *          this node...
 */
exit:
	unset_ghost_fs(&oldfs);

	return r;
}

/*
 * "send a request" to checkpoint a local process
 * an ack is send at the end of the checkpoint
 */
static inline void __chkpt_task_req(struct task_struct *task)
{
	struct siginfo info;
	int signo;
	int r;

	BUG_ON(!task);

	if (!can_be_checkpointed(task)) {
		set_task_chkpt_result(task, -EPERM);
		return;
	}

	signo = KRG_SIG_CHECKPOINT;
	info.si_errno = 0;
	info.si_pid = 0;
	info.si_uid = 0;
	si_option(info) = CHKPT_NO_OPTION;

	r = send_kerrighed_signal(signo, &info, task);
	if (r)
		BUG();

	if (!wake_up_process(task)) {
		set_task_chkpt_result(task, -EAGAIN);
	}
}

/*--------------------------------------------------------------------------*/

static inline int __get_next_chkptsn(long app_id, int original_sn)
{
	char *dirname;
	int error;
	struct nameidata nd;
	int version = original_sn;

	do {
		version++;
		dirname = get_chkpt_dir(app_id, version);
		error = path_lookup(dirname, 0, &nd);
		if (!error)
			path_put(&nd.path);
		kfree(dirname);
	} while (error != -ENOENT);

	return version;
}

/*--------------------------------------------------------------------------*/

/*
 * CHECKPOINT all the processes running _LOCALLY_ which are involved in the
 * checkpoint of an application
 *
 */
static inline int __local_do_chkpt(struct app_struct *app, int chkpt_sn)
{
	task_state_t *tsk;
	struct task_struct *tmp = NULL;
	int r;

	BUG_ON(list_empty(&app->tasks));

	app->chkpt_sn = chkpt_sn;

	r = save_local_app(app, chkpt_sn);
	if (r)
		goto exit;

	/* Checkpoint all local processes involved in the checkpoint */
	init_completion(&app->tasks_chkpted);

	list_for_each_entry(tsk, &app->tasks, next_task) {
		tmp = tsk->task;

		if (tsk->chkpt_result != PCUS_OPERATION_OK) {
			printk("Pid: %d, result: %d\n", tmp->pid, tsk->chkpt_result);
			BUG();
		}

		tsk->chkpt_result = PCUS_CHKPT_IN_PROGRESS;
		BUG_ON(tmp == current);
		__chkpt_task_req(tmp);
	}

	wait_for_completion(&app->tasks_chkpted);
	r = get_local_tasks_chkpt_result(app);
exit:
	return r;
}

struct checkpoint_request_msg {
	kerrighed_node_t requester;
	long app_id;
	int chkpt_sn;
	int flags;
};

static void handle_do_chkpt(struct rpc_desc *desc, void *_msg, size_t size)
{
	struct checkpoint_request_msg *msg = _msg;
	struct app_struct *app = find_local_app(msg->app_id);
	struct cred *cred;
	const struct cred *old_cred = NULL;
	int r;

	BUG_ON(!app);

	BUG_ON(app->cred);
	cred = prepare_creds();
	if (!cred) {
		r = -ENOMEM;
		goto send_res;
	}
	r = unpack_creds(desc, cred);
	if (r) {
		put_cred(cred);
		goto send_res;
	}
	old_cred = override_creds(cred);
	app->cred = cred;

	app->checkpoint.flags = msg->flags;

	r = __local_do_chkpt(app, msg->chkpt_sn);

send_res:
	r = send_result(desc, r);
	if (r) /* an error as occured on other node */
		goto error;

	r = local_chkpt_shared(desc, app, msg->chkpt_sn);

	r = send_result(desc, r);
	if (r)
		goto error;

	r = send_terminal_id(desc, app);
	if (r)
		goto error;

error:
	clear_shared_objects(app);
	if (app->cred) {
		app->cred = NULL;
		revert_creds(old_cred);
		put_cred(cred);
	}
}

static int global_do_chkpt(struct app_kddm_object *obj, int flags)
{
	struct rpc_desc *desc;
	struct checkpoint_request_msg msg;
	int r , err_rpc, one_terminal;

	obj->chkpt_sn = __get_next_chkptsn(obj->app_id,
					   obj->chkpt_sn);

	/* prepare message */
	msg.requester = kerrighed_node_id;
	msg.app_id = obj->app_id;
	msg.chkpt_sn = obj->chkpt_sn;
	msg.flags = flags;

	desc = rpc_begin_m(APP_DO_CHKPT, &obj->nodes);
	err_rpc = rpc_pack_type(desc, msg);
	if (err_rpc)
		goto err_rpc;
	err_rpc = pack_creds(desc, current_cred());
	if (err_rpc)
		goto err_rpc;

	/* waiting results from the nodes hosting the application */
	r = app_wait_returns_from_nodes(desc, obj->nodes);
	if (r)
		goto err_chkpt;

	err_rpc = rpc_pack_type(desc, r);
	if (err_rpc)
		goto err_rpc;

	r = global_chkpt_shared(desc, obj);
	if (r)
		goto err_chkpt;

	err_rpc = rpc_pack_type(desc, r);
	if (err_rpc)
		goto err_rpc;

	r = rcv_terminal_id(desc, obj->nodes, &one_terminal);
	if (r)
		goto err_rpc;

	r = save_app_kddm_object(obj, one_terminal);
	if (r)
		goto exit;

err_chkpt:
	err_rpc = rpc_pack_type(desc, r);
	if (err_rpc)
		goto err_rpc;
exit_rpc:
	rpc_end(desc, 0);

exit:
	return r;

err_rpc:
	r = err_rpc;
	rpc_cancel(desc);
	goto exit_rpc;
}

/*--------------------------------------------------------------------------*/

static int _freeze_app(long appid)
{
	int r;
	struct app_kddm_object *obj;

	obj = kddm_grab_object_no_ft(kddm_def_ns, APP_KDDM_ID, appid);
	if (!obj) {
		r = -ESRCH;
		goto exit_kddmput;
	}

	if (obj->state != RUNNING) {
		r = -EPERM;
		goto exit_kddmput;
	}

	r = global_stop(obj);
	if (!r)
		obj->state = FROZEN;

exit_kddmput:
	kddm_put_object(kddm_def_ns, APP_KDDM_ID, appid);
	return r;
}

static int _unfreeze_app(long appid, int signal)
{
	int r;
	struct app_kddm_object *obj;

	obj = kddm_grab_object_no_ft(kddm_def_ns, APP_KDDM_ID, appid);
	if (!obj) {
		r = -ESRCH;
		goto exit_kddmput;
	}

	if (obj->state == RUNNING) {
		r = -EPERM;
		goto exit_kddmput;
	}

	r = global_unfreeze(obj, signal);

exit_kddmput:
	kddm_put_object(kddm_def_ns, APP_KDDM_ID, appid);
	return r;
}

static int _checkpoint_frozen_app(struct checkpoint_info *info)
{
	int r;
	int prev_chkpt_sn;
	struct app_kddm_object *obj;

	obj = kddm_grab_object_no_ft(kddm_def_ns, APP_KDDM_ID, info->app_id);
	if (!obj) {
		r = -ESRCH;
		goto exit_kddmput;
	}

	if (obj->state != FROZEN) {
		r = -EPERM;
		goto exit_kddmput;
	}

	prev_chkpt_sn = obj->chkpt_sn;

	r = global_do_chkpt(obj, info->flags);

	info->chkpt_sn = obj->chkpt_sn;
	if (r)
		obj->chkpt_sn = prev_chkpt_sn;

exit_kddmput:
	kddm_put_object(kddm_def_ns, APP_KDDM_ID, info->app_id);
	return r;
}

/*--------------------------------------------------------------------------*/
/*--------------------------------------------------------------------------*/

static inline int create_app_folder(long app_id, int chkpt_sn)
{
	ghost_fs_t oldfs;
	struct path prev_root;
	int r;

	__set_ghost_fs(&oldfs);
	chroot_to_physical_root(&prev_root);

	r = mkdir_chkpt_path(app_id, chkpt_sn);

	chroot_to_prev_root(&prev_root);
	unset_ghost_fs(&oldfs);

	return r;
}

long get_appid(const struct checkpoint_info *info)
{
	long r;

	/* check if user is stupid ;-) */
	if (info->app_id < 0 ||
	    (info->signal < 0 || info->signal >= SIGRTMIN)) {
		r = -EINVAL;
		goto exit;
	}

	if (info->flags & APP_FROM_PID)
		r = get_appid_from_pid(info->app_id);
	else
		r = info->app_id;

exit:
	return r;
}

int app_freeze(struct checkpoint_info *info)
{
	int r = -EPERM;
	long app_id = get_appid(info);

	if (app_id < 0) {
		r = app_id;
		goto exit;
	}

	/* check that an application does not try to freeze itself */
	if (current->application && current->application->app_id == app_id) {
		r = -EPERM;
		goto exit;
	}

	info->app_id = app_id;

	r = _freeze_app(app_id);

exit:
	return r;
}

int app_unfreeze(struct checkpoint_info *info)
{
	int r = -EPERM;
	long app_id = get_appid(info);

	if (app_id < 0) {
		r = app_id;
		goto exit;
	}

	BUG_ON(current->application && current->application->app_id == app_id);
	info->app_id = app_id;

	r = _unfreeze_app(app_id, info->signal);
exit:
	return r;
}

int app_chkpt(struct checkpoint_info *info)
{
       int r = -EPERM;
       long app_id = get_appid(info);

       if (app_id < 0) {
               r = app_id;
               goto exit;
       }

       /* check that an application does not try to checkpoint itself */
       if (current->application && current->application->app_id == app_id) {
               r = -EPERM;
               goto exit;
       }

       info->app_id = app_id;

       r = _checkpoint_frozen_app(info);
exit:
       return r;
}

void application_checkpoint_rpc_init(void)
{
	rpc_register_void(APP_DO_CHKPT, handle_do_chkpt, 0);
}
