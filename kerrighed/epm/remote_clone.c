/*
 *  kerrighed/epm/remote_clone.c
 *
 *  Copyright (C) 1999-2006 INRIA, Universite de Rennes 1, EDF
 *  Copyright (C) 2006-2007 Pascal Gallard - Kerlabs, Louis Rilling - Kerlabs
 *  Copyright (C) 2008 Louis Rilling - Kerlabs
 */

#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/completion.h>
#include <linux/freezer.h>
#include <kerrighed/krginit.h>
#include <kerrighed/sys/types.h>
#include <kerrighed/pid.h>
#include <kerrighed/hotplug.h>
#include <kerrighed/action.h>
#include <kerrighed/ghost.h>
#ifdef CONFIG_KRG_SCHED
#include <kerrighed/scheduler/placement.h>
#endif
#include <net/krgrpc/rpcid.h>
#include <net/krgrpc/rpc.h>

#define MODULE_NAME "remote clone"

#include "debug_epm.h"

#include "network_ghost.h"

struct vfork_done_proxy {
	struct completion *waiter_vfork_done;
	kerrighed_node_t waiter_node;
};

static struct kmem_cache *vfork_done_proxy_cachep;

static void *cluster_started;

int krg_do_fork(unsigned long clone_flags,
		unsigned long stack_start,
		struct pt_regs *regs,
		unsigned long stack_size,
		int __user *parent_tidptr,
		int __user *child_tidptr,
		int trace)
{
	struct task_struct *task = current;
#ifdef CONFIG_KRG_SCHED
	kerrighed_node_t distant_node;
#else
	static kerrighed_node_t distant_node = -1;
#endif
	struct epm_action remote_clone;
	struct rpc_desc *desc;
	struct completion vfork;
	pid_t remote_pid = -1;
	int retval = -ENOSYS;

	if (!cluster_started)
		goto out;

	if ((clone_flags &
	     ~(CSIGNAL |
	       CLONE_CHILD_CLEARTID | CLONE_CHILD_SETTID |
	       CLONE_VFORK | CLONE_SYSVSEM | CLONE_UNTRACED))
	    || trace)
		/* Unsupported clone flags are requested. Abort */
		goto out;

	if (!task->sighand->krg_objid || !task->signal->krg_objid
	    || !task->task_obj || !task->children_obj) {
		retval = -EPERM;
		goto out;
	}

	retval = krg_action_start(task, EPM_REMOTE_CLONE);
	DEBUG(DBG_RCLONE, 3, "action_start: retval=%d\n", retval);
	if (retval)
		goto out;

#ifdef CONFIG_KRG_SCHED
	distant_node = new_task_node(task);
#else
	if (distant_node < 0)
		distant_node = kerrighed_node_id;
	distant_node = krgnode_next_online_in_ring(distant_node);
#endif
	DEBUG(DBG_RCLONE, 2, "%d(%s) -> %d\n",
	      task_pid_knr(current), current->comm, distant_node);
	if (distant_node < 0 || distant_node == kerrighed_node_id) {
		DEBUG(DBG_RCLONE, 1, "No need to use distant_fork\n");
		goto out_action_stop;
	}

	retval = -ENOMEM;
	desc = rpc_begin(RPC_EPM_REMOTE_CLONE, distant_node);
	if (!desc)
		goto out_action_stop;

	remote_clone.type = EPM_REMOTE_CLONE;
	remote_clone.remote_clone.target = distant_node;
	remote_clone.remote_clone.clone_flags = clone_flags;
	remote_clone.remote_clone.stack_start = stack_start;
	remote_clone.remote_clone.stack_size = stack_size;
	remote_clone.remote_clone.from_pid = task_pid_knr(task);
	remote_clone.remote_clone.from_tgid = task_tgid_knr(task);
	remote_clone.remote_clone.parent_tidptr = parent_tidptr;
	remote_clone.remote_clone.child_tidptr = child_tidptr;
	if (clone_flags & CLONE_VFORK) {
		init_completion(&vfork);
		remote_clone.remote_clone.vfork = &vfork;
	}

	remote_pid = send_task(desc, task, regs, &remote_clone);

	if (remote_pid < 0)
		rpc_cancel(desc);
	rpc_end(desc, 0);

	if (remote_pid > 0 && (clone_flags & CLONE_VFORK)) {
		freezer_do_not_count();
		wait_for_completion(&vfork);
		freezer_count();
	}

out_action_stop:
	krg_action_stop(task, EPM_REMOTE_CLONE);

out:
	DEBUG(DBG_RCLONE, 1, "remote_pid=%d\n", remote_pid);

	return remote_pid;
}

static void handle_remote_clone(struct rpc_desc *desc, void *msg, size_t size)
{
	struct epm_action *action = msg;
	struct task_struct *task;

	DEBUG(DBG_RCLONE, 1, "start\n");
	task = recv_task(desc, action);
	if (!task) {
		rpc_cancel(desc);
		DEBUG(DBG_RCLONE, 1, "failed\n");
		return;
	}

	DEBUG(DBG_RCLONE, 1, "0x%p:%d\n", task, task_pid_knr(task));
	krg_action_stop(task, EPM_REMOTE_CLONE);

	DEBUG(DBG_RCLONE, 3, "before wake up\n");
	wake_up_new_task(task, CLONE_VM);
	DEBUG(DBG_RCLONE, 1, "done\n");
}

bool in_krg_do_fork(void)
{
	return task_tgid_knr(krg_current) != krg_current->signal->krg_objid;
}

static inline struct vfork_done_proxy *vfork_done_proxy_alloc(void)
{
	return kmem_cache_alloc(vfork_done_proxy_cachep, GFP_KERNEL);
}

static inline void vfork_done_proxy_free(struct vfork_done_proxy *proxy)
{
	kmem_cache_free(vfork_done_proxy_cachep, proxy);
}

int export_vfork_done(struct epm_action *action,
		      ghost_t *ghost, struct task_struct *task)
{
	struct vfork_done_proxy proxy;
	int retval = 0;

	switch (action->type) {
	case EPM_MIGRATE:
		if (!task->vfork_done)
			break;
		if (task->remote_vfork_done) {
			proxy = *(struct vfork_done_proxy *)task->vfork_done;
		} else {
			proxy.waiter_vfork_done = task->vfork_done;
			proxy.waiter_node = kerrighed_node_id;
		}
		retval = ghost_write(ghost, &proxy, sizeof(proxy));
		break;
	case EPM_REMOTE_CLONE:
		if (action->remote_clone.clone_flags & CLONE_VFORK) {
			proxy.waiter_vfork_done = action->remote_clone.vfork;
			proxy.waiter_node = kerrighed_node_id;
			retval = ghost_write(ghost, &proxy, sizeof(proxy));
		}
		break;
	default:
		if (task->vfork_done)
			retval = -ENOSYS;
	}

	return retval;
}

static int vfork_done_proxy_install(struct task_struct *task,
				    struct vfork_done_proxy *proxy)
{
	struct vfork_done_proxy *p = vfork_done_proxy_alloc();
	int retval = -ENOMEM;

	if (!p)
		goto out;
	*p = *proxy;
	task->vfork_done = (struct completion *)p;
	task->remote_vfork_done = 1;
	retval = 0;

out:
	return retval;
}

int import_vfork_done(struct epm_action *action,
		      ghost_t *ghost, struct task_struct *task)
{
	struct vfork_done_proxy tmp_proxy;
	int retval = 0;

	switch (action->type) {
	case EPM_MIGRATE:
		if (!task->vfork_done)
			break;

		retval = ghost_read(ghost, &tmp_proxy, sizeof(tmp_proxy));
		if (unlikely(retval))
			goto out;

		if (tmp_proxy.waiter_node == kerrighed_node_id) {
			task->vfork_done = tmp_proxy.waiter_vfork_done;
			task->remote_vfork_done = 0;
			break;
		}

		retval = vfork_done_proxy_install(task, &tmp_proxy);
		break;
	case EPM_REMOTE_CLONE:
		if (action->remote_clone.clone_flags & CLONE_VFORK) {
			retval = ghost_read(ghost, &tmp_proxy, sizeof(tmp_proxy));
			if (unlikely(retval))
				goto out;
			retval = vfork_done_proxy_install(task, &tmp_proxy);
			break;
		}
		/* Fallthrough */
	default:
		task->vfork_done = NULL;
	}

out:
	return retval;
}

void unimport_vfork_done(struct task_struct *task)
{
	struct completion *vfork_done = task->vfork_done;
	if (vfork_done && task->remote_vfork_done)
		vfork_done_proxy_free((struct vfork_done_proxy *)vfork_done);
}

/* Called after having successfuly migrated out task */
void cleanup_vfork_done(struct task_struct *task)
{
	struct completion *vfork_done = task->vfork_done;
	if (vfork_done) {
		task->vfork_done = NULL;
		if (task->remote_vfork_done)
			vfork_done_proxy_free((struct vfork_done_proxy *)vfork_done);
	}
}

static void handle_vfork_done(struct rpc_desc *desc, void *data, size_t size)
{
	struct completion *vfork_done = *(struct completion **)data;

	complete(vfork_done);
}

void krg_vfork_done(struct completion *vfork_done)
{
	struct vfork_done_proxy *proxy = (struct vfork_done_proxy *)vfork_done;

	rpc_async(PROC_VFORK_DONE, proxy->waiter_node,
		  &proxy->waiter_vfork_done, sizeof(proxy->waiter_vfork_done));
	vfork_done_proxy_free(proxy);
}

void register_remote_clone_hooks(void)
{
	hook_register(&cluster_started, (void *)true);
}

int epm_remote_clone_start(void)
{
	unsigned long cache_flags = SLAB_PANIC;

#ifdef CONFIG_DEBUG_SLAB
	cache_flags |= SLAB_POISON;
#endif
	vfork_done_proxy_cachep = KMEM_CACHE(vfork_done_proxy, cache_flags);

	if (rpc_register_void(RPC_EPM_REMOTE_CLONE, handle_remote_clone, 0))
		BUG();
	if (rpc_register_void(PROC_VFORK_DONE, handle_vfork_done, 0))
		BUG();

	return 0;
}

void epm_remote_clone_exit(void)
{
}
