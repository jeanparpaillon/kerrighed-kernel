/*
 *  kerrighed/epm/app_restart.c
 *
 *  Copyright (C) 1999-2006 INRIA, Universite de Rennes 1, EDF
 *  Copyright (C) 2007-2008 Matthieu Fertré - INRIA
 */

#include <linux/sched.h>
#include <linux/compile.h>
#include <linux/version.h>
#include <linux/cred.h>
#include <kerrighed/task.h>
#include <kerrighed/children.h>
#include <kerrighed/pid.h>
#include <kerrighed/application.h>
#include <kerrighed/app_shared.h>
#include <kerrighed/remote_cred.h>
#include <kerrighed/ghost.h>
#include <kerrighed/ghost_helpers.h>
#include <kerrighed/physical_fs.h>
#include <kerrighed/hotplug.h>
#include <net/krgrpc/rpcid.h>
#include <net/krgrpc/rpc.h>
#include <kddm/kddm.h>
#include "../pid.h"
#include "../restart.h"
#include "../epm_internal.h"
#include "app_utils.h"

static int restore_app_kddm_object(struct app_kddm_object *obj,
				   long app_id, int chkpt_sn)
{
	ghost_fs_t oldfs;
	ghost_t *ghost;
	long r_appid;
	int r_chkpt_sn;
	int r = 0;
	int r_magic, magic = 4342338;
	u32 linux_version;
	char compile_info[MAX_GHOST_STRING];

	__set_ghost_fs(&oldfs);

	ghost = create_file_ghost(GHOST_READ, app_id, chkpt_sn,
				  "global.bin");

	if (IS_ERR(ghost)) {
		r = PTR_ERR(ghost);
		app_error(__krg_action_to_str(EPM_RESTART), r, app_id,
			  "Fail to open file /var/chkpt/%ld/v%d/global.bin",
			  app_id, chkpt_sn);
		goto err_open;
	}

	/* check some information about the Linux kernel version */
	r = ghost_read(ghost, &linux_version, sizeof(linux_version));
	if (r)
		goto err_read;
	if (linux_version != LINUX_VERSION_CODE)
		goto err_kernel_version;

	r = ghost_read_string(ghost, compile_info);
	if (r)
		goto err_read;
	if (strncmp(UTS_MACHINE, compile_info, MAX_GHOST_STRING))
		goto err_kernel_version;

	r = ghost_read_string(ghost, compile_info);
	if (r)
		goto err_read;
#ifndef CONFIG_KRG_DEBUG
	if (strncmp(UTS_VERSION, compile_info, MAX_GHOST_STRING))
		goto err_kernel_version;
#endif

	r = ghost_read_string(ghost, compile_info);
	if (r)
		goto err_read;
#ifndef CONFIG_KRG_DEBUG
	if (strncmp(LINUX_COMPILE_TIME, compile_info, MAX_GHOST_STRING))
		goto err_kernel_version;
#endif

	r = ghost_read_string(ghost, compile_info);
	if (r)
		goto err_read;
	if (strncmp(LINUX_COMPILE_BY, compile_info, MAX_GHOST_STRING))
		goto err_kernel_version;

	r = ghost_read_string(ghost, compile_info);
	if (r)
		goto err_read;
	if (strncmp(LINUX_COMPILE_HOST, compile_info, MAX_GHOST_STRING))
		goto err_kernel_version;

	r = ghost_read_string(ghost, compile_info);
	if (r)
		goto err_read;
	if (strncmp(LINUX_COMPILER, compile_info, MAX_GHOST_STRING))
		goto err_kernel_version;

	/* check some information about the checkpoint itself */
	r = ghost_read_type(ghost, r_appid);
	if (r)
		goto err_read;

	if (r_appid != app_id) {
		r = -E_CR_BADDATA;
		goto err_read;
	}

	r = ghost_read_type(ghost, r_chkpt_sn);
	if (r)
		goto err_read;

	if (r_chkpt_sn != chkpt_sn) {
		r = -E_CR_BADDATA;
		goto err_read;
	}

	/* initialize app_kddm_object */
	obj->app_id = app_id;
	obj->chkpt_sn = chkpt_sn;

	r = ghost_read(ghost, &obj->nodes, sizeof(obj->nodes));
	if (r)
		goto err_read;

	r = ghost_read(ghost, &obj->user_data, sizeof(obj->user_data));
	if (r)
		goto err_read;

	r = ghost_read_type(ghost, r_magic);
	if (r)
		goto err_read;

	if (r_magic != magic) {
		r = -E_CR_BADDATA;
		goto err_read;
	}

err_read:
	/* End of the really interesting part */
	ghost_close(ghost);

err_open:
	unset_ghost_fs(&oldfs);

	return r;

err_kernel_version:
	r = -E_CR_BADDATA;
	app_error(__krg_action_to_str(EPM_RESTART), r, app_id,
		  "checkpoint was done on another kernel");
	goto err_read;
}

static int was_checkpointed(struct app_struct *app, pid_t pid)
{
	/* What is the right way to check that ? */

	int error;
	struct nameidata nd;
	struct prev_root prev_root;

	char *filename = get_chkpt_filebase(app->app_id, app->chkpt_sn,
					    "task_%d.bin", pid);
	if (IS_ERR(filename))
		return PTR_ERR(filename);

	chroot_to_physical_root(&prev_root);
	error = path_lookup(filename, 0, &nd);
	chroot_to_prev_root(&prev_root);
	if (!error)
		path_put(&nd.path);
	kfree(filename);

	if (!error)
		return 1;

	return 0;
}

static int read_task_parent_links(struct app_struct *app, ghost_t *ghost,
				  pid_t pid)
{
	int r = 0;
	task_state_t *task_desc = NULL;
	pid_t tgid, parent, real_parent, real_parent_tgid;
	pid_t pgrp, session;

	r = ghost_read(ghost, &tgid, sizeof(pid_t));
	if (r)
		goto err_read;
	r = ghost_read(ghost, &parent, sizeof(pid_t));
	if (r)
		goto err_read;
	r = ghost_read(ghost, &real_parent, sizeof(pid_t));
	if (r)
		goto err_read;
	r = ghost_read(ghost, &real_parent_tgid, sizeof(pid_t));
	if (r)
		goto err_read;

	if (pid == tgid) {
		r = ghost_read(ghost, &pgrp, sizeof(pid_t));
		if (r)
			goto err_read;
		r = ghost_read(ghost, &session, sizeof(pid_t));
		if (r)
			goto err_read;
	} else {
		pgrp = 0;
		session = 0;
	}

	if (app->restart.substitution_pgrp && !was_checkpointed(app, pgrp))
		pgrp = app->restart.substitution_pgrp;

	if (app->restart.substitution_sid && !was_checkpointed(app, session))
		session = app->restart.substitution_sid;

	task_desc = alloc_task_state_from_pids(pid, tgid,
					       parent,
					       real_parent,
					       real_parent_tgid,
					       pgrp, session);

	if (IS_ERR(task_desc)) {
		r = PTR_ERR(task_desc);
		goto err_alloc;
	}

	mutex_lock(&app->mutex);
	list_add_tail(&task_desc->next_task, &app->tasks);
	mutex_unlock(&app->mutex);

err_read:
err_alloc:
	return r;
}

static int restore_local_app(long app_id, int chkpt_sn,
			     kerrighed_node_t node_id, int duplicate,
			     pid_t substitution_pgrp, pid_t substitution_sid)
{
	int r = 0;
	ghost_fs_t oldfs;
	ghost_t *ghost;
	pid_t pid;
	pid_t null = -1;
	pid_t prev = -1;

	struct app_struct *app = NULL;
	kerrighed_node_t r_node_id;

	__set_ghost_fs(&oldfs);

	ghost = create_file_ghost(GHOST_READ, app_id, chkpt_sn,
				  "node_%d.bin", node_id);

	if (IS_ERR(ghost)) {
		r = PTR_ERR(ghost);
		app_error(__krg_action_to_str(EPM_RESTART), r, app_id,
			  "Fail to open file /var/chkpt/%ld/v%d/node_%u.bin",
			  app_id, chkpt_sn, node_id);
		goto err_open;
	}

	if (node_id == kerrighed_node_id || !duplicate) {
		app = new_local_app(app_id);
		if (IS_ERR(app)) {
			r = PTR_ERR(app);
			if (r == -EEXIST)
				/*
				 * cleaning of a previous failed restart is
				 * in progress
				 */
				r = -EAGAIN;
			goto err_read;
		}

		krgnodes_clear(app->restart.replacing_nodes);
	} else {
		do {
			__set_current_state(TASK_UNINTERRUPTIBLE);
			schedule_timeout(HZ);
			app = find_local_app(app_id);
		} while (app == NULL);
	}

	krgnode_set(node_id, app->restart.replacing_nodes);

	app->chkpt_sn = chkpt_sn;

	/* read the node_id */
	r = ghost_read(ghost, &r_node_id, sizeof(kerrighed_node_t));
	if (r)
		goto err_read;

	if (r_node_id != node_id) {
		r = -E_CR_BADDATA;
		goto err_read;
	}

	/* get description of each process */
	r = ghost_read(ghost, &pid, sizeof(pid_t));
	if (r)
		goto err_read;

	if (pid == null) {
		/* there must be at least one process */
		r = -E_CR_BADDATA;
		goto err_read;
	}

	app->restart.substitution_pgrp = substitution_pgrp;
	app->restart.substitution_sid = substitution_sid;

	while (pid != null) {

		r = read_task_parent_links(app, ghost, pid);
		if (r)
			goto err_read;

		/* next! */
		prev = pid;
		r = ghost_read(ghost, &pid, sizeof(pid_t));
		if (r)
			goto err_read;

		/* a process must to not be twice in the checkpoint! */
		BUG_ON(pid == prev);
	}

err_read:
	/* End of the really interesting part */
	ghost_close(ghost);

err_open:
	unset_ghost_fs(&oldfs);

	/* the local app_struct will be deleted later in case of error */
	return r;
}

/*--------------------------------------------------------------------------*/

struct init_restart_msg {
	kerrighed_node_t requester;
	long app_id;
	int chkpt_sn;
	int recovery;
	pid_t substitution_pgrp;
	pid_t substitution_sid;
};

static void handle_init_restart(struct rpc_desc *desc, void *_msg, size_t size)
{
	struct init_restart_msg *msg = _msg;
	kerrighed_node_t n = kerrighed_node_id;
	int duplicate = 0;
	const struct cred *old_cred;
	int r;

	if (msg->recovery) {
		r = rpc_unpack_type(desc, n);
		if (r)
			goto err_rpc;
		r = rpc_unpack_type(desc, duplicate);
		if (r)
			goto err_rpc;
	}

	old_cred = unpack_override_creds(desc);
	if (IS_ERR(old_cred)) {
		r = PTR_ERR(old_cred);
		goto send_res;
	}

	r = restore_local_app(msg->app_id, msg->chkpt_sn, n, duplicate,
			      msg->substitution_pgrp, msg->substitution_sid);

	revert_creds(old_cred);
send_res:
	r = rpc_pack_type(desc, r);
	if (r)
		goto err_rpc;

	return;

err_rpc:
	rpc_cancel(desc);
	return;
}

static inline kerrighed_node_t
__find_node_for_restart(kerrighed_node_t *first_avail_node,
			int *duplicate,
			struct app_kddm_object *obj,
			kerrighed_node_t node_id)
{
	int n;

	/* looking for a node not involved in the application */
	for (n = krgnode_next_online(*first_avail_node);
	     n < KERRIGHED_MAX_NODES;
	     n = krgnode_next_online(n)) {

		if (!krgnode_isset(n, obj->nodes)) {
			krgnode_set(n, obj->nodes);
			goto out;
		}
	}

	/* all nodes are implied in the application,
	   selecting the first existing node... */
	for (n = krgnode_next_online(0); n < KERRIGHED_MAX_NODES;
	     n = krgnode_next_online(n)) {
		*first_avail_node = n+1;
		*duplicate = 1;
		goto out;
	}

	BUG();

out:
	*first_avail_node = n+1;
	return n;
}

static int global_init_restart(struct app_kddm_object *obj, int chkpt_sn, int flags)
{
	struct rpc_desc *desc;
	struct init_restart_msg msg;
	krgnodemask_t nodes, nodes_to_replace;
	kerrighed_node_t prev_available_node = 0;
	kerrighed_node_t node, recovery_node;
	int duplicate = 0;
	int r;

	r = restore_app_kddm_object(obj, obj->app_id, chkpt_sn);
	if (r)
		goto exit;

	/* prepare message */
	msg.requester = kerrighed_node_id;
	msg.app_id = obj->app_id;
	msg.chkpt_sn = chkpt_sn;
	msg.recovery = 0;

	if (flags & APP_REPLACE_PGRP_SID) {
		struct pid *pid;
		msg.substitution_pgrp = task_pgrp_knr(current);
		msg.substitution_sid = task_session_knr(current);

		pid = task_pgrp(current);
		r = cr_create_pid_kddm_object(pid);
		if (r)
			goto exit;

		pid = task_session(current);
		r = cr_create_pid_kddm_object(pid);
		if (r)
			goto exit;

	} else {
		msg.substitution_pgrp = 0;
		msg.substitution_sid = 0;
	}

	/* prepare nodes vector */
	krgnodes_clear(nodes);
	krgnodes_clear(nodes_to_replace);
	for_each_krgnode_mask(node, obj->nodes){
		if (likely(krgnode_online(node)))
			krgnode_set(node, nodes);
		else
			krgnode_set(node, nodes_to_replace);
	}

	if (!krgnodes_empty(nodes)) {
		desc = rpc_begin_m(APP_INIT_RESTART, kddm_def_ns->rpc_comm, &nodes);
		if (!desc) {
			r = -ENOMEM;
			goto exit;
		}

		r = rpc_pack_type(desc, msg);
		if (r)
			goto err_rpc;
		r = pack_creds(desc, current_cred());
		if (r)
			goto err_rpc;

		/* waiting results */
		r = app_wait_returns_from_nodes(desc, nodes);
		rpc_end(desc, 0);
	}

	/* some nodes may be unavailable */
	msg.recovery = 1;
	for_each_krgnode_mask(node, nodes_to_replace) {
		duplicate = 0;

		recovery_node = __find_node_for_restart(
			&prev_available_node, &duplicate, obj, node);

		krgnode_set(recovery_node, nodes);

		desc = rpc_begin(APP_INIT_RESTART, kddm_def_ns->rpc_comm, recovery_node);
		if (!desc) {
			r = -ENOMEM;
			goto exit;
		}

		r = rpc_pack_type(desc, msg);
		if (r)
			goto err_rpc;

		r = rpc_pack_type(desc, node);
		if (r)
			goto err_rpc;

		r = rpc_pack_type(desc, duplicate);
		if (r)
			goto err_rpc;

		r = pack_creds(desc, current_cred());
		if (r)
			goto err_rpc;

		r = rpc_unpack_type_from(desc, recovery_node, r);
		if (r)
			goto err_rpc;

		rpc_end(desc, 0);
	}

	krgnodes_copy(obj->nodes, nodes);
exit:
	return r;

err_rpc:
	rpc_cancel(desc);
	rpc_end(desc, 0);
	goto exit;
}

/*--------------------------------------------------------------------------*/

enum process_role {
	THREAD_LEADER,
	PGRP_LEADER,
	SESSION_LEADER,
	NOT_A_LEADER,
};

static inline int is_thread_leader(task_state_t *t)
{
	return (t->restart.tgid == t->restart.pid);
}

static inline int is_pgrp_leader(task_state_t *t)
{
	return (t->restart.pgrp == t->restart.pid);
}

static inline int is_session_leader(task_state_t *t)
{
	return (t->restart.session == t->restart.pid);
}

static inline int __restart_process(struct app_struct *app,
				    task_state_t *t)
{
	int r = 0;
	int flags = 0;
	struct task_struct *task;

	if (t->restart.pgrp == app->restart.substitution_pgrp)
		flags |= APP_REPLACE_PGRP;
	if (t->restart.session == app->restart.substitution_sid)
		flags |= APP_REPLACE_SID;

	task = restart_process(app, t->restart.pid, flags);

	if (IS_ERR(task)) {
		r = PTR_ERR(task);
		goto error;
	}

	/* Attach to application */
	BUG_ON(!task);
	task->application = app;
	t->task = task;
error:
	return r;
}

static int local_reserve_pid_processes(struct app_struct *app)
{
	task_state_t *t, *tfail;
	int err = 0;

	list_for_each_entry(t, &app->tasks, next_task) {
		err = reserve_pid(app->app_id, t->restart.pid);
		if (err) {
			tfail = t;
			goto error;
		}
	}

	return 0;

error:
	list_for_each_entry(t, &app->tasks, next_task) {
		if (t == tfail)
			goto err_exit;

		end_pid_reservation(t->restart.pid);
	}
err_exit:
	return err;
}

static int local_end_reserve_pid_processes(struct app_struct *app)
{
	task_state_t *t;
	int retval = 0, err = 0;

	list_for_each_entry(t, &app->tasks, next_task) {
		err = end_pid_reservation(t->restart.pid);
		if (err) {
			printk("kerrighed: %s:%d - End reservation of pid %d"
			       " fails with %d. This pid cannot be reserved"
			       " anymore until next reboot.\n",
			       __PRETTY_FUNCTION__, __LINE__,
			       t->restart.pid, err);
			retval = err;
		}
	}

	return retval;
}

typedef struct {
	int nb;
	struct list_head pids;
} pids_list_t;

typedef struct {
	pid_t pid;
	int reserved;
	struct list_head next;
} unique_pid_t;

static inline int add_unique_pid(pids_list_t *orphan_pids, pid_t pid)
{
	int r = 0;
	unique_pid_t *upid;

	/* check the pid is not already in the list */
	list_for_each_entry(upid, &(orphan_pids->pids), next) {
		if (upid->pid == pid)
			goto end;
	}

	/* add the pid in the list */
	upid = kmalloc(sizeof(unique_pid_t), GFP_KERNEL);
	if (!upid) {
		r = -ENOMEM;
		goto end;
	}
	upid->pid = pid;
	upid->reserved = 0;
	list_add_tail(&upid->next, &(orphan_pids->pids));
	orphan_pids->nb++;
end:
	return r;
}

static inline int send_pids_list(pids_list_t *orphan_pids,
				 struct rpc_desc *desc)
{
	int r = 0;
	unique_pid_t *upid;

	r = rpc_pack_type(desc, orphan_pids->nb);
	if (r)
		goto err;
	list_for_each_entry(upid, &(orphan_pids->pids), next) {
		r = rpc_pack_type(desc, upid->pid);
		if (r)
			goto err;
	}

err:
	return r;
}

static inline void free_pids_list(pids_list_t *orphan_pids)
{
	unique_pid_t *upid;
	struct list_head *element, *tmp;

	list_for_each_safe(element, tmp, &(orphan_pids->pids)) {
		upid = list_entry(element, unique_pid_t, next);

		list_del(element);
		kfree(upid);
	}
	orphan_pids->nb = 0;
}

static inline int return_orphan_sessions_and_prgps(struct app_struct *app,
						   struct rpc_desc *desc)
{
	int r = 0, checkpointed;
	task_state_t *t;
	pids_list_t orphan_pids;
	INIT_LIST_HEAD(&orphan_pids.pids);
	orphan_pids.nb = 0;

	/* first, build a list of orphan pids of session(s) and pgrp(s) */
	list_for_each_entry(t, &app->tasks, next_task) {

		if (t->restart.session != app->restart.substitution_sid) {
			checkpointed = was_checkpointed(app, t->restart.session);
			if (!checkpointed) {
				r = add_unique_pid(&orphan_pids, t->restart.session);
				if (r)
					goto err;
			} else if (checkpointed < 0) {
				r = checkpointed;
				goto err;
			}
		}

		if (t->restart.pgrp != app->restart.substitution_pgrp) {
			checkpointed = was_checkpointed(app, t->restart.pgrp);
			if (!checkpointed) {
				r = add_unique_pid(&orphan_pids, t->restart.pgrp);
				if (r)
					goto err;
			} else if (checkpointed < 0) {
				r = checkpointed;
				goto err;
			}
		}
	}

	/* secondly, send it to the global coordinator */
	r = send_pids_list(&orphan_pids, desc);

err:
	/* thirdly, free the list */
	free_pids_list(&orphan_pids);
	return r;
}

static inline int get_orphan_sessions_and_pgrps(struct rpc_desc *desc,
						krgnodemask_t nodes,
						pids_list_t *orphan_pids)
{
	kerrighed_node_t node;
	int i, r = 0;

	INIT_LIST_HEAD(&orphan_pids->pids);
	orphan_pids->nb = 0;

	for_each_krgnode_mask(node, nodes) {
		int local_orphans;
		pid_t pid;

		r = rpc_unpack_type_from(desc, node, local_orphans);
		if (r)
			goto err;

		for (i=0; i< local_orphans; i++) {
			r = rpc_unpack_type_from(desc, node, pid);
			if (r)
				goto err;

			r = add_unique_pid(orphan_pids, pid);
			if (r)
				goto err;
		}

		r = rpc_unpack_type_from(desc, node, r);
		if (r)
			goto err;
        }

out:
	return r;
err:
	free_pids_list(orphan_pids);
	goto out;
}

/* must be call for each reserved pid in error case or in normal case */
static int end_rebuild_orphan_pids(pids_list_t *orphan_pids)
{
	int r = 0, ret;
	unique_pid_t *upid;

	list_for_each_entry(upid, &(orphan_pids->pids), next) {
		if (upid->reserved) {
			ret = end_pid_reservation(upid->pid);
			if (ret)
				r |= ret;
			else
				upid->reserved = 0;
		}
	}

	return r;
}

static int rebuild_orphan_pids(long appid, pids_list_t *orphan_pids)
{
	int r = 0;
	unique_pid_t *upid;

	list_for_each_entry(upid, &(orphan_pids->pids), next) {
		BUG_ON(upid->reserved);
		r = reserve_pid(appid, upid->pid);
		if (r)
			goto err;
		upid->reserved = 1;
	}

err:
	return r;
}

static inline int local_do_restart(struct app_struct *app,
				   enum process_role role)
{
	int r = 0;
	task_state_t *t;

	BUG_ON(app == NULL);
	BUG_ON(list_empty(&app->tasks));

	list_for_each_entry(t, &app->tasks, next_task) {

		if ((role == SESSION_LEADER && is_session_leader(t))
		    || (role == PGRP_LEADER && is_pgrp_leader(t)
			&& !t->task)
		    || (role == THREAD_LEADER && is_thread_leader(t)
			&& !t->task)
		    || (role == NOT_A_LEADER && !t->task)) {

			BUG_ON(t->task);

			r = __restart_process(app, t);
			if (r)
				goto exit;
		}
	}
exit:
	return r;
}

static int local_replace_parent(struct app_struct *app,
				const task_identity_t *requester,
				pid_t *root_pid)
{
	task_state_t *t;
	int r = 0, checkpointed;

	list_for_each_entry(t, &app->tasks, next_task) {

		checkpointed = was_checkpointed(app, t->restart.parent);

		if (!checkpointed) {
			/*
			 * parent was not checkpointed we will reparent to the
			 * restart cmd
			 */
			t->restart.parent = requester->pid;
			t->restart.real_parent = requester->pid;
			t->restart.real_parent_tgid = requester->tgid;

			*root_pid = t->restart.tgid;
		} else if (checkpointed < 0) {
			r = checkpointed;
			goto err;
		}
	}

err:
	return r;
}

static int local_restore_task_object(struct app_struct *app)
{
	int r = 0;
	task_state_t *t;
	struct task_struct *task;

	list_for_each_entry(t, &app->tasks, next_task) {
		task = t->task;

		if (t->restart.parent != 1) {

			task->task_obj = __krg_task_writelock(task);

			write_lock_irq(&tasklist_lock);

			task->task_obj->parent = t->restart.parent;
			task->task_obj->real_parent = t->restart.real_parent;
			task->task_obj->real_parent_tgid =
				t->restart.real_parent_tgid;

			task->parent = baby_sitter;
			task->real_parent = baby_sitter;
			list_move(&task->sibling, &baby_sitter->children);

			write_unlock_irq(&tasklist_lock);

			__krg_task_unlock(task);
		}

		BUG_ON(task->task_obj->group_leader != t->restart.tgid);
	}

	return r;
}

static inline int task_restore_children_object(task_state_t *t)
{
	int r = 0;
	struct children_kddm_object *obj;

	if (t->restart.real_parent_tgid == 1)
		goto exit;

	BUG_ON(!(t->restart.real_parent_tgid & GLOBAL_PID_MASK));
	obj = krg_children_writelock(t->restart.real_parent_tgid);

	r = krg_new_child(obj, t->restart.real_parent, t->task);

	t->task->parent_children_obj = obj;
	krg_children_get(t->task->parent_children_obj);

	krg_children_unlock(obj);

exit:
	return r;
}

static inline int local_restore_children_object(struct app_struct *app)
{
	int r = 0;
	task_state_t *t;

	list_for_each_entry(t, &app->tasks, next_task) {
		task_restore_children_object(t);
	}

	return r;
}

static inline
struct task_struct *find_thread_leader(struct app_struct *app, task_state_t *th)
{
	task_state_t *t;
	struct task_struct *leader = NULL;

	list_for_each_entry(t, &app->tasks, next_task) {
		if (t->restart.pid == th->restart.tgid) {
			BUG_ON(t->restart.pid != t->restart.tgid);
			BUG_ON(!t->task);
			leader = t->task;
			goto found;
		}
	}
found:
	return leader;
}

static inline void local_join_relatives(struct app_struct *app)
{
	task_state_t *t;
	struct task_struct *tsk;

	list_for_each_entry(t, &app->tasks, next_task) {
		tsk = t->task;

		join_local_relatives(tsk);
		krg_pid_link_task(task_pid_knr(tsk));
	}
}

/*
 * After local_abort_restart, the local app_struct does not exist
 * anymore and the global application may not exist (it depends
 * on other nodes).
 */
static void local_abort_restart(struct app_struct *app,
				struct task_struct *fake)
{
	struct list_head *element;
	task_state_t *t;
	struct task_struct *task;
	int r;

	/* killall restarted processes */
	mutex_lock(&app->mutex);
	while (!list_empty(&app->tasks)) {
		element = (&app->tasks)->next;
		t = list_entry(element, task_state_t, next_task);
		task = t->task;
		list_del(element);
		free_task_state(t);

		if (task) {
			mutex_unlock(&app->mutex);

			/* kill the process which was already restarted */
			/*
			 * We first need to unregister the task from the
			 * application else the task will try to do it by
			 * itself.
			 */
			task->application = NULL;
			release_task(task);

			mutex_lock(&app->mutex);
		}
	}
	mutex_unlock(&app->mutex);

	/* destroying the shared objects that were restored for nothing */
	if (fake)
		destroy_shared_objects(app, fake);

	r = __delete_local_app(app);
	BUG_ON(r);
	/* The local application does not exist anymore */
}

struct restart_request_msg {
	kerrighed_node_t requester;
	long app_id;
	task_identity_t requester_task;
};

static void handle_do_restart(struct rpc_desc *desc, void *_msg, size_t size)
{
	int pid_err, r;
	pid_t root_pid = 0;
	struct restart_request_msg *msg = _msg;
	struct app_struct *app = find_local_app(msg->app_id);
	struct task_struct *fake = NULL;
	const struct cred *old_cred = NULL;

	BUG_ON(app == NULL);

	BUG_ON(app->cred);
	old_cred = unpack_override_creds(desc);
	if (IS_ERR(old_cred)) {
		r = PTR_ERR(old_cred);
		goto err_end_pid;
	}
	app->cred = current_cred();

	/* reserve pid of processes running locally */
	pid_err = local_reserve_pid_processes(app);

	r = send_result(desc, pid_err);
	if (r)
		goto error;

	/* return the list of orphan sessions and pgrp */
	r = return_orphan_sessions_and_prgps(app, desc);

	r = send_result(desc, r);
	if (r)
		goto error;

	/* restore the shared objects */
	fake = alloc_shared_fake_task_struct(app);
	if (IS_ERR(fake)) {
		r = PTR_ERR(fake);
		fake = NULL;
		goto error;
	}

#ifdef CONFIG_KRG_DEBUG
	{
		int magic;
		r = rpc_unpack_type(desc, magic);
		BUG_ON(r);
		BUG_ON(magic != 40);
	}
#endif

	r = local_restart_shared(desc, app, fake, app->chkpt_sn);
	if (r)
		goto error;

	/* restore the session leader(s) */
	r = local_do_restart(app, SESSION_LEADER);

	r = send_result(desc, r);
	if (r)
		goto error;

	/* restore the group leader(s) */
	r = local_do_restart(app, PGRP_LEADER);

	r = send_result(desc, r);
	if (r)
		goto error;

	/* restore the thread leader(s) */
	r = local_do_restart(app, THREAD_LEADER);

	r = send_result(desc, r);
	if (r)
		goto error;

	/* restore the other process(es) */
	r = local_do_restart(app, NOT_A_LEADER);

	r = send_result(desc, r);
	if (r)
		goto error;

	r = local_replace_parent(app, &msg->requester_task, &root_pid);
	if (r) {
		r = send_result(desc, r);
		goto error;
	}

	r = send_result(desc, root_pid);
	if (r)
		goto error;

	/* restore task object */
	r = local_restore_task_object(app);

	r = send_result(desc, r);
	if (r)
		goto error;

	/* restore children object */
	r = local_restore_children_object(app);

	r = send_result(desc, r);
	if (r) /* an error as occured on other node */
		goto error;

	/* join all together */
	local_join_relatives(app);

	/* complete the import of shared objects */
	local_restart_shared_complete(app, fake);

	r = local_end_reserve_pid_processes(app);

	r = send_result(desc, r);
	if (r)
		goto err_end_pid;

#ifdef CONFIG_KRG_DEBUG
	{
		int magic;
		r = rpc_unpack_type(desc, magic);
		BUG_ON(r);
		BUG_ON(magic != 48);
	}
#endif

	memset(&app->restart, 0, sizeof(app->restart));

err_end_pid:
	if (app->cred) {
		app->cred = NULL;
		revert_creds(old_cred);
	}

	if (r) {
		local_abort_restart(app, fake);
		app = NULL;
		r = rpc_pack_type(desc, r);
		rpc_cancel(desc);
	}

	if (fake)
		free_shared_fake_task_struct(fake);

	return;

error:
	if (!pid_err)
		local_end_reserve_pid_processes(app);
	goto err_end_pid;
}

static int global_do_restart(struct app_kddm_object *obj,
			     const task_identity_t *requester,
			     struct restart_request *req)
{
	struct rpc_desc *desc;
	struct restart_request_msg msg;
	pids_list_t orphan_pids;
	pid_t *root_pid = &req->root_pid;
	int r = 0, err;

	/* prepare message */
	msg.requester = kerrighed_node_id;
	msg.app_id = obj->app_id;
	msg.requester_task = *requester;

	desc = rpc_begin_m(APP_DO_RESTART, kddm_def_ns->rpc_comm, &obj->nodes);
	if (!desc)
		return -ENOMEM;

	r = rpc_pack_type(desc, msg);
	if (r)
		goto err_no_pids;
	r = pack_creds(desc, current_cred());
	if (r)
		goto err_no_pids;

	/* waiting for clients to have reserved not orphan pids */
	r = app_wait_returns_from_nodes(desc, obj->nodes);
	if (r)
		goto err_no_pids;

	r = rpc_pack_type(desc, r);
	if (r)
		goto err_no_pids;

	/* get the list of orphan sessions/groups */
	r = get_orphan_sessions_and_pgrps(desc, obj->nodes, &orphan_pids);
	if (r)
		goto err_no_pids;

	/* reserve orphan session/pgrp pids */
	r = rebuild_orphan_pids(obj->app_id, &orphan_pids);
	if (r)
		goto error;

	/* loading of shared objects */
	r = rpc_pack_type(desc, r);
	if (r)
		goto error;

#ifdef CONFIG_KRG_DEBUG
	{
		int magic = 40;
		r = rpc_pack_type(desc, magic);
		BUG_ON(r);
	}
#endif

	r = global_restart_shared(desc, obj, req);
	if (r)
		goto error;

	/* waiting for clients to have rebuilt session leader(s) */
	r = app_wait_returns_from_nodes(desc, obj->nodes);
	if (r)
		goto error;

	/* asking to rebuild group leader(s) */
	r = ask_nodes_to_continue(desc, obj->nodes, r);
	if (r)
		goto error;

	/* asking to rebuild thread leader(s) */
	r = ask_nodes_to_continue(desc, obj->nodes, r);
	if (r)
		goto error;

	/* asking to rebuild other processes */
	r = ask_nodes_to_continue(desc, obj->nodes, r);
	if (r)
		goto error;

	/* requesting root_pid */
	r = rpc_pack_type(desc, r);
	if (r)
		goto error;

	*root_pid = app_wait_returns_from_nodes(desc, obj->nodes);
	if (*root_pid < 0) {
		r = *root_pid;
		goto error;
	}

	/* asking to rebuild task_kddm_obj if r == 0 */
	r = ask_nodes_to_continue(desc, obj->nodes, r);
	if (r)
		goto error;

	/* asking to rebuild children_object if r == 0 */
	r = ask_nodes_to_continue(desc, obj->nodes, r);
	if (r)
		goto error;

	/*
	 * asking to finish the restart:
	 * - complete the restart of shared objects
	 * - complete the reservation of pids
	 */
	r = ask_nodes_to_continue(desc, obj->nodes, r);

	/* inform other nodes about current restart status */
	r = rpc_pack_type(desc, r);
	if (r)
		goto error;

#ifdef CONFIG_KRG_DEBUG
	{
		int magic = 48;
		r = rpc_pack_type(desc, magic);
		BUG_ON(r);
	}
#endif

exit_free_pid:
	err = end_rebuild_orphan_pids(&orphan_pids);
	if (err && !r)
		r = err;

	free_pids_list(&orphan_pids);

exit:
	rpc_end(desc, 0);

	return r;

error:
	rpc_cancel(desc);
	goto exit_free_pid;

err_no_pids:
	rpc_cancel(desc);
	goto exit;
}

/*--------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------*/

/**
 *  Main application restarting interface.
 *  @author Matthieu Fertré
 */
int app_restart(struct restart_request *req,
		const task_identity_t *requester)
{
	struct app_kddm_object *obj;
	int r = 0;

	membership_online_hold();

	obj = kddm_grab_object(kddm_def_ns, APP_KDDM_ID, req->app_id);

	if (obj->app_id == req->app_id) {
		r = -E_CR_APPBUSY;
		goto exit_app_busy;
	}
	obj->app_id = req->app_id;

	/* open the files and recreate the struct app_struct */
	r = global_init_restart(obj, req->chkpt_sn, req->flags);
	if (r)
		goto exit;

	/* recreate all the tasks */
	r = global_do_restart(obj, requester, req);
	if (!r)
		obj->state = APP_RESTARTED;

exit:
	if (r)
		kddm_remove_frozen_object(kddm_def_ns, APP_KDDM_ID, req->app_id);
	else
exit_app_busy:
		kddm_put_object(kddm_def_ns, APP_KDDM_ID, req->app_id);

	membership_online_release();

	return r;
}

void application_restart_rpc_init(void)
{
	rpc_register_void(APP_INIT_RESTART, handle_init_restart, 0);
	rpc_register_void(APP_DO_RESTART, handle_do_restart, 0);
}
