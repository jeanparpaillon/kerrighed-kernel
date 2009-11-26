/*
 *  kerrighed/epm/migration.c
 *
 *  Copyright (C) 1999-2006 INRIA, Universite de Rennes 1, EDF
 *  Copyright (C) 2006-2007 Pascal Gallard - Kerlabs, Louis Rilling - Kerlabs
 */

/**
 *  Migration interface.
 *  @file migration.c
 *
 *  Implementation of migration functions.
 *
 *  @author Geoffroy Vallée
 */

#include <linux/module.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/fdtable.h>
#include <linux/fs_struct.h>
#include <linux/pid_namespace.h>
#include <linux/rcupdate.h>
#include <linux/uaccess.h>
#include <kerrighed/kerrighed_signal.h>
#include <kerrighed/sys/types.h>
#include <kerrighed/krgnodemask.h>
#include <kerrighed/krginit.h>
#include <kerrighed/remote_cred.h>
#include <kerrighed/remote_syscall.h>
#ifdef CONFIG_KRG_CAP
#include <kerrighed/capabilities.h>
#endif
#ifdef CONFIG_KRG_SYSCALL_EXIT_HOOK
#include <kerrighed/syscalls.h>
#endif
#include <kerrighed/task.h>
#include <kerrighed/pid.h>
#include <kerrighed/signal.h>
#include <kerrighed/action.h>
#include <kerrighed/migration.h>
#include <kerrighed/hotplug.h>
#include <net/krgrpc/rpcid.h>
#include <net/krgrpc/rpc.h>
#include "remote_clone.h"
#include "network_ghost.h"
#include "epm_internal.h"

#if defined(CONFIG_KRG_SCHED) && defined(CONFIG_MODULE_HOOK)
struct module_hook_desc kmh_migration_start;
struct module_hook_desc kmh_migration_end;
struct module_hook_desc kmh_migration_aborted;
EXPORT_SYMBOL(kmh_migration_start);
EXPORT_SYMBOL(kmh_migration_end);
EXPORT_SYMBOL(kmh_migration_aborted);
#endif

#define si_node(info)	(*(kerrighed_node_t *)&(info)._sifields._pad)

static int migration_implemented(struct task_struct *task)
{
	int ret = 0;

	if (!task->sighand->krg_objid || !task->signal->krg_objid
	    || !task->task_obj || !task->children_obj
	    || (task->real_parent != baby_sitter
		&& !is_container_init(task->real_parent)
		&& !task->parent_children_obj))
		goto out;

	/*
	 * Note: currently useless, since CLONE_THREAD implies CLONE_VM, but
	 * will become useful when CLONE_VM will be supported.
	 */
	if (!thread_group_empty(task))
		goto out;

	task_lock(task);

	/* No kernel thread, no task sharing its VM */
	if ((task->flags & PF_KTHREAD)
	    || !task->mm
	    || atomic_read(&task->mm->mm_ltasks) > 1)
		goto out_unlock;

	/* No task sharing its signal handlers */
	/*
	 * Note: currently useless since CLONE_SIGHAND implies CLONE_VM, but
	 * will become useful when CLONE_VM will be supported
	 */
	if (atomic_read(&task->sighand->count) > 1)
		goto out_unlock;

	/* No task sharing its file descriptors table */
	if (!task->files || atomic_read(&task->files->count) > 1)
		goto out_unlock;

	/* No task sharing its fs_struct */
	if (!task->fs || task->fs->users > 1)
		goto out_unlock;

	ret = 1;
out_unlock:
	task_unlock(task);
out:
	return ret;
}

int __may_migrate(struct task_struct *task)
{
	return (pid_alive(task)
		/* check permissions */
		&& permissions_ok(task)
#ifdef CONFIG_KRG_CAP
		/* check capabilities */
		&& can_use_krg_cap(task, CAP_CAN_MIGRATE)
#endif /* CONFIG_KRG_CAP */
		&& !krg_action_pending(task, EPM_MIGRATE)
		/* Implementation limitation */
		&& migration_implemented(task));
}

int may_migrate(struct task_struct *task)
{
	int retval;

	read_lock(&tasklist_lock);
	retval = __may_migrate(task);
	read_unlock(&tasklist_lock);

	return retval;
}
EXPORT_SYMBOL(may_migrate);

void migration_aborted(struct task_struct *tsk)
{
#ifdef CONFIG_KRG_SCHED
	module_hook_call(&kmh_migration_aborted, (unsigned long) tsk);
#endif
	krg_action_stop(tsk, EPM_MIGRATE);
}

static int do_task_migrate(struct task_struct *tsk, struct pt_regs *regs,
			   kerrighed_node_t target)
{
	struct epm_action migration;
	struct rpc_desc *desc;
	pid_t remote_pid;

	BUG_ON(tsk == NULL);
	BUG_ON(regs == NULL);

	/*
	 * Check again that we actually are able to migrate tsk
	 * For instance fork() may have created a thread right after the
	 * migration request.
	 */
#ifdef CONFIG_KRG_CAP
	if (!can_use_krg_cap(tsk, CAP_CAN_MIGRATE))
		return -ENOSYS;
#endif
	if (!migration_implemented(tsk))
		return -ENOSYS;

	desc = rpc_begin(RPC_EPM_MIGRATE, tsk->nsproxy->krg_ns->rpc_comm, target);
	if (!desc)
		return -ENOMEM;

	migration.type = EPM_MIGRATE;
	migration.migrate.pid = task_pid_knr(tsk);
	migration.migrate.target = target;

	krg_unset_pid_location(tsk);

	__krg_task_writelock(tsk);
	leave_all_relatives(tsk);
	__krg_task_unlock(tsk);

	/*
	 * Prevent the migrated task from removing the sighand_struct and
	 * signal_struct copies before migration cleanup ends
	 */
	krg_sighand_pin(tsk->sighand);
	krg_signal_pin(tsk->signal);
	mm_struct_pin(tsk->mm);

	remote_pid = send_task(desc, tsk, regs, &migration);

	if (remote_pid < 0)
		rpc_cancel(desc);
	rpc_end(desc, 0);

	if (remote_pid < 0) {
		struct task_kddm_object *obj;

		mm_struct_unpin(tsk->mm);

		krg_signal_writelock(tsk->signal);
		krg_signal_unlock(tsk->signal);
		krg_signal_unpin(tsk->signal);

		krg_sighand_writelock(tsk->sighand->krg_objid);
		krg_sighand_unlock(tsk->sighand->krg_objid);
		krg_sighand_unpin(tsk->sighand);

		obj = __krg_task_writelock(tsk);
		BUG_ON(!obj);
		write_lock_irq(&tasklist_lock);
		obj->task = tsk;
		tsk->task_obj = obj;
		write_unlock_irq(&tasklist_lock);
		__krg_task_unlock(tsk);

		join_local_relatives(tsk);

		krg_set_pid_location(tsk);
	} else {
		BUG_ON(remote_pid != task_pid_knr(tsk));
		/* Do not notify a task having done vfork() */
		cleanup_vfork_done(tsk);
	}

	return remote_pid > 0 ? 0 : remote_pid;
}

static void krg_task_migrate(int sig, struct siginfo *info,
			     struct pt_regs *regs)
{
	struct task_struct *tsk = current;
	int r = 0;

	r = do_task_migrate(tsk, regs, si_node(*info));

	if (!r) {
#ifdef CONFIG_KRG_SCHED
		module_hook_call(&kmh_migration_end, 0);
#endif
		do_exit_wo_notify(0); /* Won't return */
	}

	/* Migration failed */
	migration_aborted(tsk);
}

/**
 *  Process migration handler.
 *  @author Renaud Lottiaux, Geoffroy Vallée
 */
static void handle_migrate(struct rpc_desc *desc, void *msg, size_t size)
{
	struct epm_action *action = msg;
	struct task_struct *task;

	task = recv_task(desc, action);
	if (!task) {
		rpc_cancel(desc);
		return;
	}

#ifdef CONFIG_KRG_SCHED
	module_hook_call(&kmh_migration_end, (unsigned long)task);
#endif
	krg_action_stop(task, EPM_MIGRATE);

	wake_up_new_task(task, CLONE_VM);
}

/* Expects tasklist_lock locked */
static int do_migrate_process(struct task_struct *task,
			      kerrighed_node_t destination_node_id)
{
	struct siginfo info;
	int retval;

	if (!krgnode_online(destination_node_id))
		return -ENONET;

	if (destination_node_id == kerrighed_node_id)
		return 0;

	if (!migration_implemented(task)) {
		printk("do_migrate_process: trying to migrate a thread"
		       " of a multi-threaded process!\n Aborting...\n");
		return -ENOSYS;
	}

	retval = krg_action_start(task, EPM_MIGRATE);
	if (retval)
		return retval;

#ifdef CONFIG_KRG_SCHED
	module_hook_call(&kmh_migration_start, (unsigned long)task);
#endif

	info.si_errno = 0;
	info.si_pid = 0;
	info.si_uid = 0;
	si_node(info) = destination_node_id;

	retval = send_kerrighed_signal(KRG_SIG_MIGRATE, &info, task);
	if (retval)
		migration_aborted(task);

	return retval;
}

/* Kernel-level API */

int __migrate_linux_threads(struct task_struct *task,
			    enum migration_scope scope,
			    kerrighed_node_t dest_node)
{
	int r = -EPERM;

	read_lock(&tasklist_lock);
	if (!__may_migrate(task))
		goto exit;

	switch (scope) {
	case MIGR_THREAD:
		r = do_migrate_process(task, dest_node);
		break;
	case MIGR_GLOBAL_PROCESS:
		/* Until distributed threads are re-enabled, we can do it! */
#if 0
		printk("MIGR_GLOBAL_PROCESS: Not implemented\n");
		r = -ENOSYS;
		break;
#endif
	case MIGR_LOCAL_PROCESS: {
		struct task_struct *t;

		/*
		 * TODO: Wait until all threads are able to migrate before
		 * migrating the first one.
		 */
		t = task;
		do {
			r = do_migrate_process(t, dest_node);
			if (r)
				break;
		} while ((t = next_thread(t)) != task);

		break;
	} default:
		printk("migr_scope: %d\n", scope);
		BUG();
	}

exit:
	read_unlock(&tasklist_lock);

	return r;
}
EXPORT_SYMBOL(__migrate_linux_threads);

struct migration_request_msg {
	pid_t pid;
	enum migration_scope scope;
	kerrighed_node_t destination_node_id;
};

static int handle_migrate_remote_process(struct rpc_desc *desc,
					 void *_msg, size_t size)
{
	struct migration_request_msg msg;
	struct pid *pid;
	const struct cred *old_cred;
	int retval;

	pid = krg_handle_remote_syscall_begin(desc, _msg, size,
					      &msg, &old_cred);
	if (IS_ERR(pid)) {
		retval = PTR_ERR(pid);
		goto out;
	}
	retval = __migrate_linux_threads(pid_task(pid, PIDTYPE_PID), msg.scope,
					 msg.destination_node_id);
	krg_handle_remote_syscall_end(pid, old_cred);
out:
	return retval;
}

static int migrate_remote_process(pid_t pid,
				  enum migration_scope scope,
				  kerrighed_node_t destination_node_id)
{
	struct migration_request_msg msg;

	msg.pid = pid;
	msg.scope = scope;
	msg.destination_node_id = destination_node_id;

	return krg_remote_syscall_simple(PROC_REQUEST_MIGRATION, pid,
					 &msg, sizeof(msg));
}

int migrate_linux_threads(pid_t pid,
			  enum migration_scope scope,
			  kerrighed_node_t dest_node)
{
	struct task_struct *task;
	int r;

	/* Check the destination node */
	/* Just an optimization to avoid doing a useless remote request */
	if (!krgnode_online(dest_node))
		return -ENONET;

	rcu_read_lock();
	task = find_task_by_vpid(pid);

	if (!task || (task->flags & PF_AWAY)) {
		rcu_read_unlock();
		return migrate_remote_process(pid, scope, dest_node);
	}

	r = __migrate_linux_threads(task, scope, dest_node);
	rcu_read_unlock();

	return r;
}
EXPORT_SYMBOL(migrate_linux_threads);

/* Syscall API */

/**
 *  System call to migrate a process
 *  @author Geoffroy Vallée, Pascal Gallard
 *
 *  @param tgid		tgid of the process to migrate.
 *  @param dest_node	Id of the node to migrate the process to.
 */
int sys_migrate_process(pid_t tgid, kerrighed_node_t dest_node)
{
	if (dest_node < 0 || dest_node >= KERRIGHED_MAX_NODES)
		return -EINVAL;
	return migrate_linux_threads(tgid, MIGR_GLOBAL_PROCESS, dest_node);
}

/**
 *  System call to migrate a thread.
 *  @author Geoffroy Vallée
 *
 *  @param pid		pid of the thread to migrate.
 *  @param dest_node	Id of the node to migrate the process to.
 */
int sys_migrate_thread(pid_t pid, kerrighed_node_t dest_node)
{
	if (dest_node < 0 || dest_node >= KERRIGHED_MAX_NODES)
		return -EINVAL;
	return migrate_linux_threads(pid, MIGR_THREAD, dest_node);
}

#ifdef CONFIG_KRG_SYSCALL_EXIT_HOOK
void krg_syscall_exit(long syscall_nr)
{
	__migrate_linux_threads(current, MIGR_LOCAL_PROCESS,
				krgnode_next_online_in_ring(kerrighed_node_id));
}
#endif

int epm_migration_start(void)
{
	krg_handler[KRG_SIG_MIGRATE] = krg_task_migrate;
	if (rpc_register_void(RPC_EPM_MIGRATE, handle_migrate, 0))
		BUG();
	if (rpc_register_int(PROC_REQUEST_MIGRATION,
			     handle_migrate_remote_process, 0))
		BUG();

	return 0;
}

void epm_migration_exit(void)
{
}
