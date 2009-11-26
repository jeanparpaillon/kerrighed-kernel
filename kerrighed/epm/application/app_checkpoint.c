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
#include <kerrighed/sys/checkpoint.h>
#include <kerrighed/ghost.h>
#include <kerrighed/ghost_helpers.h>
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

static int save_app_kddm_object(struct app_kddm_object *obj)
{
	ghost_fs_t oldfs;
	ghost_t *ghost;
	int magic = 4342338;
	int r = 0, err;
	u32 linux_version;

	__set_ghost_fs(&oldfs);

	ghost = create_file_ghost(GHOST_WRITE, obj->app_id, obj->chkpt_sn,
				  "global.bin");

	if (IS_ERR(ghost)) {
		r = PTR_ERR(ghost);
		app_error(__krg_action_to_str(EPM_CHECKPOINT), r, obj->app_id,
			  "Fail to create file /var/chkpt/%ld/v%d/global.bin",
			  obj->app_id, obj->chkpt_sn);
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
	r = ghost_write(ghost, &magic, sizeof(magic));
	if (r)
		goto err_write;

err_write:
	/* End of the really interesting part */
	err = ghost_close(ghost);
	if (!r)
		r = err;
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
	struct pid_namespace *ns;
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

	ns = task_active_pid_ns(t->task);
	obj = krg_parent_children_readlock(t->task);
	if (obj) {
		r = krg_get_parent(obj, t->task, &parent, &real_parent);
		BUG_ON(r);
		rcu_read_lock();
		real_parent_tgid = krg_get_real_parent_tgid(t->task,
							    krg_pid_ns_root(ns));
		rcu_read_unlock();
		krg_children_unlock(obj);
	} else {
		read_lock(&tasklist_lock);
		parent = real_parent = task_pid_knr(ns->child_reaper);
		read_unlock(&tasklist_lock);
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
	int r = 0, err;
	int null = -1;
	task_state_t *t;

	__set_ghost_fs(&oldfs);

	ghost = create_file_ghost(GHOST_WRITE, app->app_id, chkpt_sn,
				  "node_%d.bin", kerrighed_node_id);

	if (IS_ERR(ghost)) {
		r = PTR_ERR(ghost);
		app_error(__krg_action_to_str(EPM_CHECKPOINT), r, app->app_id,
			  "Fail to create file /var/chkpt/%ld/v%d/node_%u.bin",
			  app->app_id, chkpt_sn, kerrighed_node_id);
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
	list_for_each_entry(t, &app->tasks, next_task) {
		r = write_task_parent_links(t, ghost);
		if (r)
			goto err_write;
	}

	/* end of file marker */
	r = ghost_write(ghost, &null, sizeof(int));
	if (r)
		goto err_write;
	r = ghost_write(ghost, &null, sizeof(int));

err_write:
	/* End of the really interesting part */
	err = ghost_close(ghost);
	if (!r)
		r = err;

exit:
	unset_ghost_fs(&oldfs);

	return r;
}

/*
 * "send a request" to checkpoint a local process
 * an ack is send at the end of the checkpoint
 */
static void __chkpt_task_req(struct app_struct *app, task_state_t *tsk)
{
	struct task_struct *task = tsk->task;
	ghost_t *ghost;
	int r;

	BUG_ON(!task);

	tsk->checkpoint.ghost = NULL;
	if (!can_be_checkpointed(task)) {
		__set_task_result(task, -EPERM);
		return;
	}

	ghost = create_file_ghost(GHOST_WRITE,
				  app->app_id,
				  app->chkpt_sn,
				  "task_%d.bin",
				  task_pid_knr(task));
	if (IS_ERR(ghost)) {
		r = PTR_ERR(ghost);
		app_error(__krg_action_to_str(EPM_CHECKPOINT), r, app->app_id,
			  "Fail to create file /var/chkpt/%ld/v%d/task_%d.bin "
			  "to checkpoint process %d (%s)",
			  app->app_id, app->chkpt_sn,
			  task_pid_knr(task),
			  task_pid_knr(task), task->comm);
		__set_task_result(task, r);
		return;
	}
	tsk->checkpoint.ghost = ghost;

	complete(&tsk->checkpoint.completion);
}

ghost_t *get_task_chkpt_ghost(struct app_struct *app, struct task_struct *task)
{
	ghost_t *ghost = NULL;
	task_state_t *t;

	mutex_lock(&app->mutex);

	list_for_each_entry(t, &app->tasks, next_task)
		if (task == t->task) {
			ghost = t->checkpoint.ghost;
			break;
		}

	mutex_unlock(&app->mutex);

	return ghost;
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
		if (IS_ERR(dirname)) {
			version = PTR_ERR(dirname);
			goto error;
		}

		error = path_lookup(dirname, 0, &nd);
		if (!error)
			path_put(&nd.path);
		kfree(dirname);
	} while (error != -ENOENT);

error:
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

	/* application is frozen, locking here is paranoiac */
	mutex_lock(&app->mutex);

	r = save_local_app(app, chkpt_sn);
	if (r)
		goto err;

	/* Checkpoint all local processes involved in the checkpoint */
	init_completion(&app->tasks_chkpted);

	list_for_each_entry(tsk, &app->tasks, next_task) {
		tmp = tsk->task;

		tsk->checkpoint.result = PCUS_CHKPT_IN_PROGRESS;
		BUG_ON(tmp == current);
		__chkpt_task_req(app, tsk);
	}

	mutex_unlock(&app->mutex);

	wait_for_completion(&app->tasks_chkpted);
	r = get_local_tasks_chkpt_result(app);
out:
	return r;
err:
	mutex_unlock(&app->mutex);
	goto out;
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
	const struct cred *old_cred = NULL;
	int r;

	BUG_ON(!app);

	BUG_ON(app->cred);
	old_cred = unpack_override_creds(desc);
	if (IS_ERR(old_cred)) {
		r = PTR_ERR(old_cred);
		goto send_res;
	}
	app->cred = current_cred();

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

error:
	cr_free_mm_exclusions(app);

	clear_shared_objects(app);
	if (app->cred) {
		app->cred = NULL;
		revert_creds(old_cred);
	}
}

static int global_do_chkpt(struct app_kddm_object *obj, int flags)
{
	struct rpc_desc *desc;
	struct checkpoint_request_msg msg;
	int r, err_rpc;

	r = __get_next_chkptsn(obj->app_id, obj->chkpt_sn);
	if (r < 0)
		goto exit;

	obj->chkpt_sn = r;

	/* prepare message */
	msg.requester = kerrighed_node_id;
	msg.app_id = obj->app_id;
	msg.chkpt_sn = obj->chkpt_sn;
	msg.flags = flags;

	desc = rpc_begin_m(APP_DO_CHKPT, kddm_def_ns->rpc_comm, &obj->nodes);
	if (!desc) {
		r = -ENOMEM;
		goto exit;
	}

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

	r = save_app_kddm_object(obj);
	if (r)
		goto exit;

	err_rpc = rpc_pack_type(desc, r);
	if (err_rpc)
		goto err_rpc;
exit_rpc:
	rpc_end(desc, 0);

exit:
	return r;

err_rpc:
	r = err_rpc;
err_chkpt:
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
		app_error("freeze", r, appid,
			  "Application does not exist");
		goto exit_kddmput;
	}

	if (obj->state == APP_RUNNING_CS) {
		r = -EAGAIN;
		app_error("freeze", r, appid,
			  "Application is in critical section");
		goto exit_kddmput;
	}

	if (obj->state != APP_RUNNING) {
		r = -EPERM;
		app_error("freeze", r, appid,
			  "Application is not running");
		goto exit_kddmput;
	}

	r = global_stop(obj);
	if (!r)
		obj->state = APP_FROZEN;

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
		app_error("unfreeze", r, appid,
			  "Application does not exist");
		goto exit_kddmput;
	}

	if (obj->state == APP_RUNNING) {
		r = -EPERM;
		app_error("unfreeze", r, appid,
			  "Application is already running");
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
		app_error(__krg_action_to_str(EPM_CHECKPOINT), r, info->app_id,
			  "Application does not exist");
		goto exit_kddmput;
	}

	if (obj->state != APP_FROZEN) {
		r = -EPERM;
		app_error(__krg_action_to_str(EPM_CHECKPOINT), r, info->app_id,
			  "Application is not frozen");
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

static void handle_cr_exclude(struct rpc_desc *desc, void *_msg, size_t size)
{
	struct app_struct *app;
	struct cr_mm_region mm_region;
	int r;
	long *app_id = _msg;

	app = find_local_app(*app_id);

	do {
		r = rpc_unpack(desc, 0, &mm_region, sizeof(struct cr_mm_region));
		if (r)
			goto error;

		r = cr_exclude_mm_region(app, mm_region.pid, mm_region.addr,
					 mm_region.size);
		if (r)
			goto error;

	} while (mm_region.next);

out:
	return;
error:
	rpc_cancel(desc);
	goto out;
}

int app_cr_exclude(struct cr_mm_region *mm_regions)
{
	long app_id;
	struct app_kddm_object *obj;
	struct rpc_desc *desc;
	struct cr_mm_region *element;
	int r;

	if (!mm_regions)
		return -EINVAL;

	app_id = get_appid_from_pid(task_pid_knr(current));
	if (app_id < 0)
		return app_id;

	obj = kddm_grab_object_no_ft(kddm_def_ns, APP_KDDM_ID, app_id);
	if (!obj) {
		r = -ESRCH;
		app_error(__krg_action_to_str(EPM_CHECKPOINT), r, app_id,
			  "Application does not exist");
		goto exit_kddmput;
	}

	if (obj->state == APP_RUNNING_CS) {
		r = -EAGAIN;
		app_error(__krg_action_to_str(EPM_CHECKPOINT), r, app_id,
			  "Application is in critical section");
		goto exit_kddmput;
	}

	if (obj->state != APP_RUNNING) {
		r = -EPERM;
		app_error(__krg_action_to_str(EPM_CHECKPOINT), r, app_id,
			  "Application is not running");
		goto exit_kddmput;
	}

	desc = rpc_begin_m(APP_EXCL_MM_REGION, kddm_def_ns->rpc_comm, &obj->nodes);
	if (!desc) {
		r = -ENOMEM;
		goto exit_kddmput;
	}

	r = rpc_pack_type(desc, app_id);
	if (r)
		goto exit_rpc;

	element = mm_regions;
	while (element) {
		r = rpc_pack(desc, 0, element, sizeof(struct cr_mm_region));
		if (r)
			goto exit_rpc;

		element = element->next;
	}

	rpc_end(desc, 0);
exit_kddmput:
	kddm_put_object(kddm_def_ns, APP_KDDM_ID, app_id);
	return r;
exit_rpc:
	rpc_cancel(desc);
	goto exit_kddmput;
}

/*--------------------------------------------------------------------------*/
/*--------------------------------------------------------------------------*/

static long get_appid(const char *action, const struct checkpoint_info *info)
{
	long r;

	/* check if user is stupid ;-) */
	if ((info->app_id < 0 || !(info->app_id & GLOBAL_PID_MASK))
	    || (info->signal < 0 || info->signal >= SIGRTMIN)) {
		r = -EINVAL;
		app_error(action, r, info->app_id,
			  "User request contains invalid value(s)");
		goto exit;
	}

	if (info->flags & APP_FROM_PID) {
		r = get_appid_from_pid(info->app_id);
		if (r < 0)
			app_error(action, r, -1,
				  "Fail to find an application hosting "
				  "process %ld",
				  info->app_id);
	} else
		r = info->app_id;

exit:
	return r;
}

int app_freeze(struct checkpoint_info *info)
{
	int r = -EPERM;
	long app_id = get_appid("freeze", info);

	if (app_id < 0) {
		r = app_id;
		goto exit;
	}

	/* check that an application does not try to freeze itself */
	if (current->application && current->application->app_id == app_id) {
		r = -EPERM;
		app_error("freeze", r, app_id,
			  "Application is trying to freeze itself");
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
	long app_id = get_appid("unfreeze", info);

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
	long app_id = get_appid(__krg_action_to_str(EPM_CHECKPOINT), info);

	if (app_id < 0) {
		r = app_id;
		goto exit;
	}

	/* check that an application does not try to checkpoint itself */
	if (current->application && current->application->app_id == app_id) {
		r = -EPERM;
		app_error(__krg_action_to_str(EPM_CHECKPOINT), r, app_id,
			  "trying to checkpoint itself");
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
	rpc_register_void(APP_EXCL_MM_REGION, handle_cr_exclude, 0);
}
