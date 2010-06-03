/*
 *  kerrighed/epm/application.c
 *
 *  Copyright (C) 1999-2006 INRIA, Universite de Rennes 1, EDF
 *  Copyright (C) 2007-2008 Matthieu Fertré - INRIA
 */

#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <linux/cred.h>
#include <linux/hashtable.h>
#include <kerrighed/remote_cred.h>
#include <kerrighed/pid.h>
#include <kerrighed/libproc.h>
#include <kerrighed/application.h>
#include <kerrighed/app_shared.h>
#include <kerrighed/ghost_helpers.h>
#include <kerrighed/kerrighed_signal.h>
#include <kerrighed/action.h>
#include <net/krgrpc/rpcid.h>
#include <net/krgrpc/rpc.h>
#include <kddm/kddm.h>
#include "../epm_internal.h"
#include "../checkpoint.h"
#include "app_checkpoint.h"
#include "app_frontier.h"
#include "app_restart.h"
#include "app_utils.h"

/*--------------------------------------------------------------------------*
 *--------------------------------------------------------------------------*/

static hashtable_t *app_struct_table;

struct app_struct *find_local_app(long app_id)
{
	return (struct app_struct *)hashtable_find(app_struct_table, app_id);
}

/*--------------------------------------------------------------------------*
 *--------------------------------------------------------------------------*/

static struct kddm_set *app_kddm_set;
static struct kmem_cache *app_kddm_obj_cachep;
static struct kmem_cache *app_struct_cachep;
static struct kmem_cache *task_state_cachep;

static int app_alloc_object(struct kddm_obj *obj_entry,
			    struct kddm_set *kddm, objid_t objid)
{
	struct app_kddm_object *a;

	a = kmem_cache_alloc(app_kddm_obj_cachep, GFP_KERNEL);
	if (a == NULL)
		return -ENOMEM;

	a->app_id = 0;
	a->chkpt_sn = 0;
	a->state = APP_RUNNING;
	a->user_data = 0;
	obj_entry->object = a;

	return 0;
}

static int app_remove_object(void *obj, struct kddm_set *kddm,
			     objid_t objid)
{
	struct app_kddm_object *a = obj;
	kmem_cache_free(app_kddm_obj_cachep, a);

	return 0;
}

static struct iolinker_struct app_io_linker = {
	.linker_name = "app ",
	.linker_id = APP_LINKER,
	.alloc_object = app_alloc_object,
	.remove_object = app_remove_object,
	.default_owner = global_pid_default_owner,
};

/*--------------------------------------------------------------------------*/

struct app_struct *new_local_app(long app_id)
{
	struct app_struct *app;
	int r;

	app = kmem_cache_zalloc(app_struct_cachep, GFP_KERNEL);
	if (!app) {
		app = ERR_PTR(-ENOMEM);
		goto exit;
	}

	app->app_id = app_id;
	app->chkpt_sn = 0;

	mutex_init(&app->mutex);
	init_completion(&app->tasks_chkpted);
	INIT_LIST_HEAD(&app->tasks);
	app->shared_objects.root = RB_ROOT;
	spin_lock_init(&app->shared_objects.lock);

	/*
	 * it may fail if:
	 * - a previous restart has failed and cleaning is not
	 *   yet completely finished.
	 * - there is a lack of memory
	 */
	r = hashtable_add_unique(app_struct_table, app_id, app);
	if (r)
		goto error_hash;

exit:
	return app;

error_hash:
	mutex_destroy(&app->mutex);
	kmem_cache_free(app_struct_cachep, app);
	app = ERR_PTR(r);
	goto exit;
}

int __delete_local_app(struct app_struct *app)
{
	mutex_lock(&app->mutex);
	/* should be really rare ...*/
	if (!local_tasks_list_empty(app))
		goto exit_wo_deleting;

	hashtable_remove(app_struct_table, app->app_id);
	mutex_unlock(&app->mutex);

	clear_shared_objects(app);
	mutex_destroy(&app->mutex);
	kmem_cache_free(app_struct_cachep, app);
	return 0;

exit_wo_deleting:
	mutex_unlock(&app->mutex);
	return -EAGAIN;
}

void delete_app(struct app_struct *app)
{
	int r = 0;
	struct app_kddm_object *obj = NULL;

	mutex_lock(&app->mutex);
	if (!local_tasks_list_empty(app)) {
		mutex_unlock(&app->mutex);
		return;
	}
	mutex_unlock(&app->mutex);

	obj = _kddm_grab_object_no_ft(app_kddm_set, app->app_id);
	if (!obj) /* another process was running delete_app concurrently */
		goto exit;

	r = __delete_local_app(app);
	if (r)
		goto exit_put;

	krgnode_clear(kerrighed_node_id, obj->nodes);

	if (krgnodes_empty(obj->nodes)) {
		_kddm_remove_frozen_object(app_kddm_set, obj->app_id);
		goto exit;
	}

exit_put:
	_kddm_put_object(app_kddm_set, obj->app_id);
exit:
	return;
}

/*--------------------------------------------------------------------------*/

int create_application(struct task_struct *task)
{
	struct app_struct *app;
	struct app_kddm_object *obj;
	long app_id = task_pid_knr(task);
	int r = 0;

	obj = _kddm_grab_object(app_kddm_set, app_id);

	if (obj->app_id == app_id) {
		_kddm_put_object(app_kddm_set, app_id);
		r = -EBUSY;
		goto exit;
	}

	obj->app_id = app_id;
	obj->chkpt_sn = 0;

	krgnodes_clear(obj->nodes);
	krgnode_set(kerrighed_node_id, obj->nodes);
	app = new_local_app(app_id);
	if (IS_ERR(app)) {
		r = PTR_ERR(app);
		task->application = NULL;
		_kddm_remove_frozen_object(app_kddm_set, app_id);
		goto exit;
	}

	register_task_to_app(app, task);
	_kddm_put_object(app_kddm_set, app_id);
exit:
	return r;
}

static inline task_state_t *__alloc_task_state(void)
{
	task_state_t *t;
	t = kmem_cache_alloc(task_state_cachep, GFP_KERNEL);
	if (!t) {
		t = ERR_PTR(-ENOMEM);
		goto err_mem;
	}
	t->result = 0;
err_mem:
	return t;
}

static inline task_state_t *alloc_task_state_from_task(
	struct task_struct *task)
{
	task_state_t *t = __alloc_task_state();

	BUG_ON(!task);

	if (!IS_ERR(t))
		t->task = task;

	return t;
}

task_state_t *alloc_task_state_from_pids(pid_t pid,
					 pid_t tgid,
					 pid_t parent,
					 pid_t real_parent,
					 pid_t real_parent_tgid,
					 pid_t pgrp,
					 pid_t session)
{
	task_state_t *t = __alloc_task_state();

	if (IS_ERR(t))
		goto err;

	t->task = NULL;
	t->restart.pid = pid;
	t->restart.tgid = tgid;
	t->restart.parent = parent;
	t->restart.real_parent = real_parent;
	t->restart.real_parent_tgid = real_parent_tgid;
	t->restart.pgrp = pgrp;
	t->restart.session = session;

err:
	return t;
}

void free_task_state(task_state_t *t)
{
	kmem_cache_free(task_state_cachep, t);
}

int register_task_to_app(struct app_struct *app,
			 struct task_struct *task)
{
	int r = 0;
	task_state_t *t;

	BUG_ON(!app);
	BUG_ON(!task);

	t = alloc_task_state_from_task(task);
	if (IS_ERR(t)) {
		r = PTR_ERR(t);
		goto err;
	}
	t->result = PCUS_RUNNING;

	mutex_lock(&app->mutex);
	task->application = app;
	list_add_tail(&t->next_task, &app->tasks);
	mutex_unlock(&app->mutex);

err:
	return r;
}

static int register_task_to_appid(long app_id,
				  struct task_struct *task)
{
	int r;
	struct app_struct *app;
	struct app_kddm_object *obj;

	obj = _kddm_grab_object_no_ft(app_kddm_set, app_id);
	BUG_ON(!obj);

	app = find_local_app(app_id);
	if (!app) {
		app = new_local_app(app_id);
		if (IS_ERR(app)) {
			r = PTR_ERR(app);
			goto error;
		}
		krgnode_set(kerrighed_node_id, obj->nodes);
	}
	r = register_task_to_app(app, task);

error:
	_kddm_put_object(app_kddm_set, app_id);
	return r;
}

void unregister_task_to_app(struct app_struct *app, struct task_struct *task)
{
	struct list_head *tmp, *element;
	task_state_t *t;

	BUG_ON(!app);

	/* remove the task */
	mutex_lock(&app->mutex);
	task->application = NULL;

	list_for_each_safe(element, tmp, &app->tasks) {
		t = list_entry(element, task_state_t, next_task);
		if (task == t->task) {
			list_del(element);
			free_task_state(t);
			goto exit;
		}
	}
	BUG();

exit:
	mutex_unlock(&app->mutex);
	delete_app(app);
}

/*--------------------------------------------------------------------------*/

/* app->mutex must be taken */
task_state_t *__set_task_result(struct task_struct *task, int result)
{
	struct app_struct *app;
	task_state_t *t, *ret = NULL;
	int done_for_all_tasks = 1;

	app = task->application;

	list_for_each_entry(t, &app->tasks, next_task) {
		if (task == t->task) {
			ret = t;

			if (t->result == PCUS_RUNNING)
				/* result has been forced to cancel operation */
				goto out;

			t->result = result;
		}

		if (t->result == PCUS_CHKPT_IN_PROGRESS ||
		    t->result == PCUS_STOP_STEP1 ||
		    t->result == PCUS_STOP_STEP2)
			done_for_all_tasks = 0;
	}

	if (done_for_all_tasks)
		complete(&app->tasks_chkpted);

out:
	BUG_ON(!ret);

	return ret;
}

void set_result_wait(int result)
{
	struct app_struct *app;
	task_state_t *current_state;

	app = current->application;
	BUG_ON(!app);

	mutex_lock(&app->mutex);
	current_state = __set_task_result(current, result);

	init_completion(&current_state->checkpoint.completion);
	mutex_unlock(&app->mutex);

	/*
	 * the task_state_t can disappear only:
	 * 1) when aborting a restart
	 * 2) when the process itself exits
	 *
	 * both are impossible here, we can safely release app->mutex before
	 * waiting for the completion.
	 */
	wait_for_completion(&current_state->checkpoint.completion);
}

/* before running this method, be sure stops are completed */
static int get_local_tasks_stop_result(struct app_struct* app)
{
	int r = 0, pcus_result = 0;
	task_state_t *t;

	mutex_lock(&app->mutex);

	list_for_each_entry(t, &app->tasks, next_task) {
		pcus_result = t->result;
		BUG_ON(pcus_result == PCUS_STOP_STEP1);

		if (pcus_result == PCUS_RUNNING) {
			/* one process has been forgotten! try again!! */
			r = pcus_result;
			goto exit;
		} else if (t->task->state == TASK_DEAD) {
			/* Process is zombie !! */
			r = -E_CR_TASKDEAD;
			ckpt_err(NULL, r,
				 "Process %d (%s) of application %ld is dead"
				 " or zombie",
				 t->task->pid, t->task->comm, app->app_id);
			goto exit;
		}
		r = r | pcus_result;
	}

exit:
	mutex_unlock(&app->mutex);

	return r;
}

/* before running this method, be sure checkpoints are completed */
int get_local_tasks_chkpt_result(struct app_struct* app)
{
	int r = 0, pcus_result = 0;
	task_state_t *t;

	mutex_lock(&app->mutex);

	list_for_each_entry(t, &app->tasks, next_task) {
		pcus_result = t->result;
		if (pcus_result == PCUS_RUNNING) {
			/* one process has been forgotten! try again!! */
			r = pcus_result;
			goto exit;
		}

		if (t->checkpoint.ghost) {
			if (pcus_result < 0)
				unlink_file_ghost(t->checkpoint.ghost);
			r = ghost_close(t->checkpoint.ghost);
			t->checkpoint.ghost = NULL;
		}

		if (!r)
			r = pcus_result;
	}

exit:
	mutex_unlock(&app->mutex);

	return r;
}

/*--------------------------------------------------------------------------*/

int krg_copy_application(struct task_struct *task)
{
	int r = 0;
	task->application = NULL;

	if (!task->nsproxy->krg_ns)
		return 0;

	/* father is no more checkpointable? */
	if (!cap_raised(current->krg_caps.effective, CAP_CHECKPOINTABLE) &&
	    current->application)
		unregister_task_to_app(current->application, current);


	/* did we get the CHECKPOINTABLE capability? */
	if (!cap_raised(task->krg_caps.effective, CAP_CHECKPOINTABLE))
		return 0;

	/*
	 * father is CHECKPOINTABLE but is not associatied to an application,
	 * fix it!
	 */
	if (cap_raised(current->krg_caps.effective, CAP_CHECKPOINTABLE) &&
	    !current->application)
		r = create_application(current);

	if (r)
		goto err;

	if (current->application)
		r = register_task_to_app(current->application, task);

	/*
	 * The following can be done only when needed. Doing this will optimize
	 * the forking time.
	 */
	/* else
	   r = create_application(task);*/

err:
	return r;
}

void krg_exit_application(struct task_struct *task)
{
	if (task->application)
		unregister_task_to_app(task->application, task);
}

/*--------------------------------------------------------------------------*/

int export_application(struct epm_action *action,
		       ghost_t *ghost, struct task_struct *task)
{
	int r = 0;
	long app_id = -1;

	BUG_ON(!task);

	/* leave an application if no more checkpointable */
	if (!cap_raised(task->krg_caps.effective, CAP_CHECKPOINTABLE) &&
	    task->application)
		unregister_task_to_app(task->application, task);

	/* Lazy creation of application (step 2/2) */
	/* If process is checkpointable but not in an application
	   and action = REMOTE_CLONE, create the application */
	if (cap_raised(task->krg_caps.effective, CAP_CHECKPOINTABLE) &&
	    !task->application && action->type == EPM_REMOTE_CLONE)
		create_application(task);

	if (!task->application)
		app_id = -1;
	else
		app_id = task->application->app_id;

	r = ghost_write(ghost, &app_id, sizeof(long));

	return r;
}

int import_application(struct epm_action *action,
		       ghost_t *ghost, struct task_struct *task)
{
	int r;
	long app_id;

	task->application = NULL;

	r = ghost_read(ghost, &app_id, sizeof(long));
	if (r)
		goto out;

	if (action->type == EPM_CHECKPOINT)
		return 0;

	if (!cap_raised(task->krg_caps.effective, CAP_CHECKPOINTABLE))
		return 0;

	if (app_id == -1) {
		/* this can be done later ... (lazy creation of application) */
		/* create_application(task); */
	} else
		r = register_task_to_appid(app_id, task);
out:
	return r;
}

void unimport_application(struct epm_action *action,
			  ghost_t *ghost, struct task_struct *task)
{
	if (!task->application)
		return;

	unregister_task_to_app(task->application, task);
}

/*--------------------------------------------------------------------------*/

/* app->mutex must be held */
static void local_cancel_stop(struct app_struct *app)
{
	task_state_t *tsk;
	int r;

	list_for_each_entry(tsk, &app->tasks, next_task) {
		if (tsk->result == PCUS_RUNNING)
			goto out;
		r = krg_action_stop(tsk->task, EPM_CHECKPOINT);
		BUG_ON(r);
		if (tsk->result == PCUS_OPERATION_OK)
			complete(&tsk->checkpoint.completion);
		tsk->result = PCUS_RUNNING;
	}

out:
	return;
}

/* app->mutex must be held */
static int local_prepare_stop(struct app_struct *app)
{
	task_state_t *tsk;
	int r = 0;

	list_for_each_entry(tsk, &app->tasks, next_task) {
		if (tsk->result == PCUS_RUNNING) {
			if (!can_be_checkpointed(tsk->task)) {
				r = -EPERM;
				goto error;
			}

			/* Process is zombie !! */
			if (tsk->task->state == TASK_DEAD) {
				r = -E_CR_TASKDEAD;
				goto error;
			}

			r = krg_action_start(tsk->task, EPM_CHECKPOINT);
			if (r) {
				ckpt_err(NULL, r,
					 "krg_action_start fails for "
					 "process %d %s",
					 tsk->task->pid, tsk->task->comm);
				goto error;
			}

			tsk->result = PCUS_STOP_STEP1;
		}
	}

error:
	return r;
}

/* app->mutex must be held */
static void local_complete_stop(struct app_struct *app)
{
	task_state_t *tsk;
	struct siginfo info;
	int r, signo;

	signo = KRG_SIG_CHECKPOINT;
	info.si_errno = 0;
	info.si_pid = 0;
	info.si_uid = 0;
	si_option(info) = CHKPT_ONLY_STOP;

	list_for_each_entry(tsk, &app->tasks, next_task) {
		if (tsk->result == PCUS_STOP_STEP1) {
			tsk->result = PCUS_STOP_STEP2;
			r = send_kerrighed_signal(signo, &info, tsk->task);
			BUG_ON(r);
		}
	}
}

/* app->mutex must be NOT held */
static int local_wait_stop(struct app_struct *app)
{
	int r = PCUS_STOP_STEP2;

	while (r == PCUS_STOP_STEP2) {
		/* waiting for timeout is needed for process becoming zombie */
		wait_for_completion_timeout(&app->tasks_chkpted, 100);

		r = get_local_tasks_stop_result(app);

		/*
		 * A process may have been forgotten because it is a child of
		 * a process which has forked before handling the signal but
		 * after looping on each processes of the application
		 */
		if (r == PCUS_RUNNING) {
			r = -EAGAIN;
			goto error;
		}
	}

error:
	return r;
}

struct app_stop_msg {
	kerrighed_node_t requester;
	long app_id;
};

static void handle_app_stop(struct rpc_desc *desc, void *_msg, size_t size)
{
	int r;
	struct app_stop_msg *msg = _msg;
	struct app_struct *app;
	const struct cred *old_cred;

	app = find_local_app(msg->app_id);
	BUG_ON(!app);

	mutex_lock(&app->mutex);

	r = 0;
	old_cred = unpack_override_creds(desc);
	if (IS_ERR(old_cred))
		r = PTR_ERR(old_cred);

	/*
	 * Check there is still some processes
	 * A freeze may happen just before deletion of the local app_struct
	 */
	if (!r && list_empty(&app->tasks))
		r = -EAGAIN;

	r = send_result(desc, r);
	if (r)
		goto out_unlock;

	init_completion(&app->tasks_chkpted);

	r = local_prepare_stop(app);

	r = send_result(desc, r);
	if (r)
		goto out_cancel_stop;

	local_complete_stop(app);

	mutex_unlock(&app->mutex);

	r = local_wait_stop(app);

	r = send_result(desc, r);
	if (r)
		goto out_wait_failed;

out:
	if (!IS_ERR(old_cred))
		revert_creds(old_cred);

	if (r)
		rpc_cancel(desc);

	return;

out_wait_failed:
	mutex_lock(&app->mutex);
out_cancel_stop:
	local_cancel_stop(app);
out_unlock:
	mutex_unlock(&app->mutex);
	goto out;
}

int global_stop(struct app_kddm_object *obj)
{
	struct rpc_desc *desc;
	struct app_stop_msg msg;
	int err_rpc, r;

	/* prepare message */
	msg.requester = kerrighed_node_id;
	msg.app_id = obj->app_id;

	desc = rpc_begin_m(APP_STOP, &obj->nodes);
	err_rpc = rpc_pack_type(desc, msg);
	if (err_rpc)
		goto err_rpc;

	err_rpc = pack_creds(desc, current_cred());
	if (err_rpc)
		goto err_rpc;

	/* waiting results from the node hosting the application */
	r = app_wait_returns_from_nodes(desc, obj->nodes);
	if (r)
		goto error;

	/* asking to prepare stop */
	r = ask_nodes_to_continue(desc, obj->nodes, r);
	if (r)
		goto error;

	/* asking to complete and wait stop */
	r = ask_nodes_to_continue(desc, obj->nodes, r);
	if (r)
		goto error;

	/* informing nodes that everyting is fine */
	err_rpc = rpc_pack_type(desc, r);
	if (err_rpc)
		goto err_rpc;

exit:
	rpc_end(desc, 0);
	return r;

err_rpc:
	r = err_rpc;
error:
	rpc_cancel(desc);
	goto exit;
}

/*--------------------------------------------------------------------------*/

/* wake up a local process (blocking request) */
static void __continue_task(task_state_t *tsk, int first_run)
{
	BUG_ON(!tsk);

	krg_action_stop(tsk->task, EPM_CHECKPOINT);

	if (!first_run)
		complete(&tsk->checkpoint.completion);
	else
		wake_up_new_task(tsk->task, CLONE_VM);

	tsk->result = PCUS_RUNNING;
}

static void __local_continue(struct app_struct *app, int first_run)
{
	task_state_t *tsk;

	BUG_ON(!app);

	mutex_lock(&app->mutex);

	BUG_ON(list_empty(&app->tasks));

	/* make all the local processes of the application going back to
	 * computation */
	list_for_each_entry(tsk, &app->tasks, next_task) {
		__continue_task(tsk, first_run);
	}

	mutex_unlock(&app->mutex);
}

struct app_continue_msg {
	kerrighed_node_t requester;
	long app_id;
	int first_run;
};

static void handle_app_continue(struct rpc_desc *desc, void *_msg, size_t size)
{
	int r = 0;
	struct app_continue_msg *msg = _msg;
	struct app_struct *app = find_local_app(msg->app_id);

	BUG_ON(!app);

	__local_continue(app, msg->first_run);

	r = rpc_pack_type(desc, r);
	if (r)
		goto err;

	return;

err:
	rpc_cancel(desc);
}

static int global_continue(struct app_kddm_object *obj)
{
	struct rpc_desc *desc;
	struct app_continue_msg msg;
	int r = 0;

	/* prepare message */
	msg.requester = kerrighed_node_id;
	msg.app_id = obj->app_id;

	BUG_ON(obj->state != APP_RESTARTED && obj->state != APP_FROZEN);

	if (obj->state == APP_RESTARTED)
		msg.first_run = 1;
	else
		msg.first_run = 0;

	desc = rpc_begin_m(APP_CONTINUE, &obj->nodes);

	r = rpc_pack_type(desc, msg);
	if (r)
		goto err_rpc;

	/* waiting results from the node hosting the application */
	r = app_wait_returns_from_nodes(desc, obj->nodes);

exit:
	rpc_end(desc, 0);

	return r;

err_rpc:
	rpc_cancel(desc);
	goto exit;
}

/*--------------------------------------------------------------------------*/

static int _kill_process(task_state_t *tsk, int signal)
{
	int r;
	if (!can_be_checkpointed(tsk->task)) {
		r = -EPERM;
		goto exit;
	}

	r = kill_pid(task_pid(tsk->task), signal, 1);
	if (r)
		goto exit;

exit:
	return r;
}

static inline int __local_kill(struct app_struct *app, int signal)
{
	int retval = 0;
	int r = 0;
	task_state_t *tsk;

	BUG_ON(!app);

	mutex_lock(&app->mutex);

	BUG_ON(list_empty(&app->tasks));

	/* signal all the local processes of the application */
	list_for_each_entry(tsk, &app->tasks, next_task) {
		retval = _kill_process(tsk, signal);
		r = retval | r;
	}

	mutex_unlock(&app->mutex);

	return r;
}

struct app_kill_msg {
	kerrighed_node_t requester;
	long app_id;
	int signal;
};

static void handle_app_kill(struct rpc_desc *desc, void *_msg, size_t size)
{
	int r;
	struct app_kill_msg *msg = _msg;
	struct app_struct *app = find_local_app(msg->app_id);
	const struct cred *old_cred;

	BUG_ON(!app);

	old_cred = unpack_override_creds(desc);
	if (IS_ERR(old_cred)) {
		r = PTR_ERR(old_cred);
		goto send_res;
	}

	r = __local_kill(app, msg->signal);

	revert_creds(old_cred);

send_res:
	r = rpc_pack_type(desc, r);
	if (r)
		goto err;

	return;
err:
	rpc_cancel(desc);
}

static int global_kill(struct app_kddm_object *obj, int signal)
{
	struct rpc_desc *desc;
	struct app_kill_msg msg;
	int r = 0;

	/* prepare message */
	msg.requester = kerrighed_node_id;
	msg.app_id = obj->app_id;
	msg.signal = signal;

	desc = rpc_begin_m(APP_KILL, &obj->nodes);

	r = rpc_pack_type(desc, msg);
	if (r)
		goto err_rpc;
	r = pack_creds(desc, current_cred());
	if (r)
		goto err_rpc;

	/* waiting results from the node hosting the application */
	r = app_wait_returns_from_nodes(desc, obj->nodes);

exit:
	rpc_end(desc, 0);

	return r;

err_rpc:
	rpc_cancel(desc);
	goto exit;
}

int global_unfreeze(struct app_kddm_object *obj, int signal)
{
	int r;

	if (obj->state != APP_FROZEN
	    && obj->state != APP_RESTARTED) {
		r = -EPERM;
		goto err;
	}

	if (signal) {
		r = global_kill(obj, signal);
		if (r)
			goto err;
	}

	r = global_continue(obj);
	if (r)
		goto err;

	obj->state = APP_RUNNING;
err:
	return r;
}

int app_set_userdata(__u64 user_data)
{
	int r = 0;
	struct app_kddm_object *obj;

	if (!can_be_checkpointed(current)) {
		r = -EPERM;
		goto exit;
	}

	if (!current->application) {
		r = create_application(current);
		if (r)
			goto exit;
	}

	obj = kddm_grab_object_no_ft(kddm_def_ns, APP_KDDM_ID,
				     current->application->app_id);
	if (!obj) {
		r = -ESRCH;
		goto exit_kddmput;
	}

	obj->user_data = user_data;

exit_kddmput:
	kddm_put_object(kddm_def_ns, APP_KDDM_ID, current->application->app_id);
exit:
	return r;
}

int app_get_userdata(long _appid, int flags, __u64 *user_data)
{
	int r = 0;
	long app_id = _appid;
	struct app_kddm_object *obj;

	if (app_id < 0) {
		r = -EINVAL;
		goto exit;
	}

	if (flags & APP_FROM_PID) {
		app_id = get_appid_from_pid(_appid);
		if (app_id < 0) {
			r = app_id;
			goto exit;
		}
	}

	obj = kddm_get_object_no_ft(kddm_def_ns, APP_KDDM_ID, app_id);
	if (!obj) {
		r = -ESRCH;
		goto exit_kddmput;
	}

	*user_data = obj->user_data;

exit_kddmput:
	kddm_put_object(kddm_def_ns, APP_KDDM_ID, app_id);
exit:
	return r;
}

int app_cr_disable(void)
{
	int r = 0;
	struct app_kddm_object *obj;

	if (!can_be_checkpointed(current)) {
		r = -EPERM;
		goto exit;
	}

	if (!current->application) {
		r = create_application(current);
		if (r)
			goto exit;
	}

	obj = kddm_grab_object_no_ft(kddm_def_ns, APP_KDDM_ID,
				     current->application->app_id);
	if (!obj) {
		r = -ESRCH;
		goto exit_kddmput;
	}

	if (obj->state == APP_RUNNING_CS)
		r = -EALREADY;
	else if (obj->state == APP_RUNNING)
		obj->state = APP_RUNNING_CS;
	else
		BUG();

exit_kddmput:
	kddm_put_object(kddm_def_ns, APP_KDDM_ID, current->application->app_id);
exit:
	return r;
}

int app_cr_enable(void)
{
	int r = 0;
	struct app_kddm_object *obj;

	if (!can_be_checkpointed(current)) {
		r = -EPERM;
		goto exit;
	}

	if (!current->application) {
		r = create_application(current);
		if (r)
			goto exit;
	}

	obj = kddm_grab_object_no_ft(kddm_def_ns, APP_KDDM_ID,
				     current->application->app_id);
	if (!obj) {
		r = -ESRCH;
		goto exit_kddmput;
	}

	if (obj->state == APP_RUNNING)
		r = -EALREADY;
	else if (obj->state == APP_RUNNING_CS)
		obj->state = APP_RUNNING;
	else
		BUG();

exit_kddmput:
	kddm_put_object(kddm_def_ns, APP_KDDM_ID, current->application->app_id);
exit:
	return r;
}

void do_ckpt_msg(int err, char *fmt, ...)
{
	va_list args;
	char *buffer;

	va_start(args, fmt);
	buffer = kvasprintf(GFP_KERNEL, fmt, args);
	va_end(args);

	if (buffer) {
		printk("%s\n", buffer);
		kfree(buffer);
	} else
		printk("WARNING: Memory is low\n"
		       "Chekpoint/Restart operation failed with error %d\n",
		       err);
}

/*--------------------------------------------------------------------------*
 *                                                                          *
 *          APPLICATION CHECKPOINT SERVER MANAGEMENT                        *
 *                                                                          *
 *--------------------------------------------------------------------------*/

void application_cr_server_init(void)
{
	unsigned long cache_flags = SLAB_PANIC;
#ifdef CONFIG_DEBUG_SLAB
	cache_flags |= SLAB_POISON;
#endif

	app_struct_table = hashtable_new(5);

	/*------------------------------------------------------------------*/

	register_io_linker(APP_LINKER, &app_io_linker);

	app_kddm_set = create_new_kddm_set(kddm_def_ns, APP_KDDM_ID,
					   APP_LINKER, KDDM_CUSTOM_DEF_OWNER,
					   sizeof(struct app_kddm_object),
					   KDDM_LOCAL_EXCLUSIVE);
	if (IS_ERR(app_kddm_set))
		OOM;

	app_kddm_obj_cachep = KMEM_CACHE(app_kddm_object, cache_flags);
	app_struct_cachep = KMEM_CACHE(app_struct, cache_flags);
	task_state_cachep = KMEM_CACHE(task_and_state, cache_flags);

	rpc_register_void(APP_STOP, handle_app_stop, 0);
	rpc_register_void(APP_CONTINUE, handle_app_continue, 0);
	rpc_register_void(APP_KILL, handle_app_kill, 0);

	application_frontier_rpc_init();
	application_checkpoint_rpc_init();
	application_restart_rpc_init();
}

void application_cr_server_finalize(void)
{
	if (kerrighed_node_id == 0) {
		_destroy_kddm_set(app_kddm_set);
	}
	hashtable_free(app_struct_table);
}
