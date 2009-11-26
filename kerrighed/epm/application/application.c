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
	a->state = RUNNING;
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

	app = kmem_cache_zalloc(app_struct_cachep, GFP_KERNEL);

	app->app_id = app_id;
	app->chkpt_sn = 0;

	spin_lock_init(&app->lock);
	init_completion(&app->tasks_chkpted);
	INIT_LIST_HEAD(&app->tasks);
	app->shared_objects.root = RB_ROOT;
	spin_lock_init(&app->shared_objects.lock);

	hashtable_add(app_struct_table, app_id, app);

	return app;
}

int __delete_local_app(struct app_struct *app)
{
	spin_lock(&app->lock);
	/* should be really rare ...*/
	if (!local_tasks_list_empty(app))
		goto exit_wo_deleting;

	hashtable_remove(app_struct_table, app->app_id);
	spin_unlock(&app->lock);

	clear_shared_objects(app);
	kmem_cache_free(app_struct_cachep, app);
	return 0;

exit_wo_deleting:
	spin_unlock(&app->lock);
	return -EAGAIN;
}

void delete_app(struct app_struct *app)
{
	int r = 0;
	struct app_kddm_object *obj = NULL;

	spin_lock(&app->lock);
	if (!local_tasks_list_empty(app)) {
		spin_unlock(&app->lock);
		return;
	}
	spin_unlock(&app->lock);

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
	if (!app) {
		r = -ENOMEM;
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
	t->chkpt_result = 0;
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
	t->chkpt_result = PCUS_RUNNING;

	spin_lock(&app->lock);
	task->application = app;
	list_add_tail(&t->next_task, &app->tasks);
	spin_unlock(&app->lock);

err:
	return r;
}

int register_task_to_appid(long app_id,
			   struct task_struct *task)
{
	int r;
	struct app_struct *app;
	struct app_kddm_object *obj;

	obj = _kddm_grab_object_no_ft(app_kddm_set, app_id);
	BUG_ON(!obj);

	app = find_local_app(app_id);
	if (!app) {
		krgnode_set(kerrighed_node_id, obj->nodes);
		app = new_local_app(app_id);
	}
	r = register_task_to_app(app, task);
	_kddm_put_object(app_kddm_set, app_id);

	return r;
}

void unregister_task_to_app(struct app_struct *app, struct task_struct *task)
{
	struct list_head *tmp, *element;
	task_state_t *t;

	BUG_ON(!app);

	/* remove the task */
	spin_lock(&app->lock);
	task->application = NULL;

	list_for_each_safe(element, tmp, &app->tasks) {
		t = list_entry(element, task_state_t, next_task);
		if (task == t->task) {
			list_del(element);
			spin_unlock(&app->lock);

			free_task_state(t);
			goto exit;
		}
	}
	BUG();

exit:
	delete_app(app);
}

/*--------------------------------------------------------------------------*/

void set_task_chkpt_result(struct task_struct *task, int result)
{
	struct app_struct *app;
	struct list_head *tmp, *element;
	task_state_t *t;
	int done_for_all_tasks = 1;

	app = task->application;

	if (!app)
		return;

	spin_lock(&app->lock);

	list_for_each_safe(element, tmp, &app->tasks) {
		t = list_entry(element, task_state_t, next_task);
		if (task == t->task)
			t->chkpt_result = result;

		if (t->chkpt_result == PCUS_CHKPT_IN_PROGRESS ||
		    t->chkpt_result == PCUS_STOP_IN_PROGRESS)
			done_for_all_tasks = 0;
	}

	spin_unlock(&app->lock);

	if (done_for_all_tasks)
		complete(&app->tasks_chkpted);
}

/* before running this method, be sure checkpoints are completed */
int get_local_tasks_chkpt_result(struct app_struct* app)
{
	int r = 0, pcus_result = 0;
	task_state_t *t;

	list_for_each_entry(t, &app->tasks, next_task) {
		pcus_result = t->chkpt_result;
		if (pcus_result == PCUS_RUNNING) {
			/* one process has been forgotten! try again!! */
			return pcus_result;
		} else if (pcus_result == PCUS_STOP_IN_PROGRESS)
			/* Process is zombie !! */
			if (t->task->state == TASK_DEAD)
				return -E_CR_TASKDEAD;

		r = r | pcus_result;
	}

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
		register_task_to_appid(app_id, task);
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

/* make a local process sleeping (blocking request) */
static inline int __stop_task(struct task_struct *task)
{
	struct siginfo info;
	int signo;
	int retval;

	BUG_ON(!task);
	BUG_ON(task == current);

	if (!can_be_checkpointed(task)) {
		retval = -EPERM;
		goto exit;
	}

	retval = krg_action_start(task, EPM_CHECKPOINT);
	if (retval) {
		printk("krg_action_start returns %d (%d %s)\n",
		       retval, task->pid, task->comm);
		goto exit;
	}

	signo = KRG_SIG_CHECKPOINT;
	info.si_errno = 0;
	info.si_pid = 0;
	info.si_uid = 0;
	si_option(info) = CHKPT_ONLY_STOP;

	retval = send_kerrighed_signal(signo, &info, task);
	if (retval)
		BUG();

exit:
	return retval;
}

static inline int __local_stop(struct app_struct *app)
{
	task_state_t *tsk;
	int r = 0;

	BUG_ON(list_empty(&app->tasks));

stop_all_running:
	/* Stop all the local processes of the application */
	init_completion(&app->tasks_chkpted);

	list_for_each_entry(tsk, &app->tasks, next_task) {
		if (tsk->chkpt_result == PCUS_RUNNING) {
			tsk->chkpt_result = PCUS_STOP_IN_PROGRESS;
			r = __stop_task(tsk->task);
			if (r != 0)
				set_task_chkpt_result(tsk->task, r);
		}
	}
	r = PCUS_STOP_IN_PROGRESS;

	while (r == PCUS_STOP_IN_PROGRESS) {
		printk("*** wait for completion\n");

		wait_for_completion_timeout(&app->tasks_chkpted, 100);
		r = get_local_tasks_chkpt_result(app);

		/* A process may have been forgotten because it is a child of
		   a process which has forked before handling the signal but after
		   looping on each processes of the application */
		if (r == PCUS_RUNNING)
			goto stop_all_running;
	}

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
	struct cred *cred;
	const struct cred *old_cred;

	app = find_local_app(msg->app_id);
	BUG_ON(!app);

	cred = prepare_creds();
	if (!cred) {
		r = -ENOMEM;
		goto send_res;
	}
	r = unpack_creds(desc, cred);
	if (r) {
		put_cred(cred);
		goto rpc_err;
	}
	old_cred = override_creds(cred);

	r = __local_stop(app);

	revert_creds(old_cred);
	put_cred(cred);

send_res:
	r = rpc_pack_type(desc, r);

rpc_err:
	if (r)
		rpc_cancel(desc);
}


int global_stop(struct app_kddm_object *obj)
{
	struct rpc_desc *desc;
	struct app_stop_msg msg;
	int r = 0;

	/* prepare message */
	msg.requester = kerrighed_node_id;
	msg.app_id = obj->app_id;

	desc = rpc_begin_m(APP_STOP, &obj->nodes);
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

/*--------------------------------------------------------------------------*/

/* wake up a local process (blocking request) */
static inline int __continue_task(task_state_t *tsk, int first_run)
{
	int r = 0;
	BUG_ON(!tsk);

	krg_action_stop(tsk->task, EPM_CHECKPOINT);

	if (!first_run) {
		BUG_ON(tsk->task->state != TASK_UNINTERRUPTIBLE &&
		       tsk->task->state != TASK_INTERRUPTIBLE);
		if (!wake_up_process(tsk->task)) {
			r = -EAGAIN;
			goto exit;
		}
	} else {
		wake_up_new_task(tsk->task, CLONE_VM);
	}

	tsk->chkpt_result = PCUS_RUNNING;

exit:
	return r;
}

static inline int __local_continue(struct app_struct *app, int first_run)
{
	int r = 0;
	task_state_t *tsk;

	BUG_ON(!app);
	BUG_ON(list_empty(&app->tasks));

	/* make all the local processes of the application going back to
	 * computation */
	list_for_each_entry(tsk, &app->tasks, next_task) {
		r = __continue_task(tsk, first_run);
	}

	return r;
}

struct app_continue_msg {
	kerrighed_node_t requester;
	long app_id;
	int first_run;
};

static void handle_app_continue(struct rpc_desc *desc, void *_msg, size_t size)
{
	int r;
	struct app_continue_msg *msg = _msg;
	struct app_struct *app = find_local_app(msg->app_id);

	BUG_ON(!app);

	r = __local_continue(app, msg->first_run);

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

	BUG_ON(obj->state != RESTARTED && obj->state != FROZEN);

	if (obj->state == RESTARTED)
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
	BUG_ON(list_empty(&app->tasks));

	/* signal all the local processes of the application */
	list_for_each_entry(tsk, &app->tasks, next_task) {
		retval = _kill_process(tsk, signal);
		r = retval | r;
	}

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
	struct cred *cred;
	const struct cred *old_cred;

	BUG_ON(!app);

	cred = prepare_creds();
	if (!cred) {
		r = -ENOMEM;
		goto send_res;
	}
	r = unpack_creds(desc, cred);
	if (r) {
		put_cred(cred);
		goto err;
	}
	old_cred = override_creds(cred);

	r = __local_kill(app, msg->signal);

	revert_creds(old_cred);
	put_cred(cred);

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

	if (obj->state != FROZEN
	    && obj->state != RESTARTED) {
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

	obj->state = RUNNING;
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

void do_ckpt_msg(struct epm_action *action, int err, char *fmt, ...)
{
	va_list args;
	char *buffer;

	if (action && action->type != EPM_CHECKPOINT)
		return;

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
