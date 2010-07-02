/*
 *  kerrighed/epm/ghost.c
 *
 *  Copyright (C) 1999-2006 INRIA, Universite de Rennes 1, EDF
 *  Copyright (C) 2006-2007 Pascal Gallard - Kerlabs, Louis Rilling - Kerlabs
 *
 *  @author Geoffroy Vallée
 */

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/signal.h>
#include <linux/pid.h>
#include <linux/pid_namespace.h>
#include <linux/fdtable.h>
#include <linux/thread_info.h>
#include <linux/delayacct.h>
#include <linux/nsproxy.h>
#include <linux/utsname.h>
#include <linux/iocontext.h>
#include <linux/ioprio.h>
#include <linux/list.h>
#include <linux/rcupdate.h>
#include <net/net_namespace.h>
#include <kddm/kddm_info.h>
#include <kerrighed/krginit.h>
#include <kerrighed/namespace.h>
#include <kerrighed/krgsyms.h>
#include <kerrighed/children.h>
#include <kerrighed/task.h>
#include <kerrighed/signal.h>
#include <kerrighed/pid.h>
#include <kerrighed/application.h>
#include <kerrighed/app_shared.h>
#include <kerrighed/ghost.h>
#include <kerrighed/ghost_helpers.h>
#include <kerrighed/action.h>
#include <kerrighed/debug.h>
#include <asm/ptrace.h>
#include "epm_internal.h"

/* Export */

/* Arch helpers */
int export_exec_domain(struct epm_action *action,
		       ghost_t *ghost, struct task_struct *task)
{
	if (task_thread_info(task)->exec_domain != &default_exec_domain)
		return -EPERM;

	return 0;
}

int export_restart_block(struct epm_action *action,
			 ghost_t *ghost, struct task_struct *task)
{
	struct thread_info *ti = task_thread_info(task);
	enum krgsyms_val fn_id;
	int r;

	fn_id = krgsyms_export(ti->restart_block.fn);
	if (fn_id == KRGSYMS_UNDEF) {
		r = -EBUSY;
		goto out;
	}
	r = ghost_write(ghost, &fn_id, sizeof(fn_id));
	if (r)
		goto out;
	r = ghost_write(ghost, &ti->restart_block, sizeof(ti->restart_block));

out:
	return r;
}

/* Regular helpers */

/* export_thread_info() is located in <arch>/kerrighed/ghost.c */

/* export_sched() is located in kernel/sched.c */

static int export_preempt_notifiers(struct epm_action *action,
				   ghost_t *ghost, struct task_struct *task)
{
	int err = 0;

#ifdef CONFIG_PREEMPT_NOTIFIERS
	if (action->type != EPM_REMOTE_CLONE) {
		if (!hlist_empty(&task->preempt_notifiers))
			err = -EBUSY;
	}
#endif

	return err;
}

static int export_sched_info(struct epm_action *action,
			     ghost_t *ghost, struct task_struct *tsk)
{
	/* Nothing to do... */
	return 0;
}

/* export_mm() is located in kerrighed/mm/mobility.c */

static int export_binfmt(struct epm_action *action,
			 ghost_t *ghost, struct task_struct *task)
{
	int binfmt_id;

	binfmt_id = krgsyms_export(task->binfmt);
	if (binfmt_id == KRGSYMS_UNDEF)
		return -EPERM;

	return ghost_write(ghost, &binfmt_id, sizeof(int));
}

static int export_children(struct epm_action *action,
			   ghost_t *ghost, struct task_struct *task)
{
	/* Managed by children kddm object */
	return 0;
}

static int export_group_leader(struct epm_action *action,
			       ghost_t *ghost, struct task_struct *task)
{
	pid_t tgid = task_tgid_knr(task);
	int err = 0;

	if (action->type == EPM_CHECKPOINT && !thread_group_leader(task))
		err = ghost_write(ghost, &tgid, sizeof(tgid));

	return err;
}

static int export_ptraced(struct epm_action *action,
			  ghost_t *ghost, struct task_struct *task)
{
	int err = 0;

	if (action->type != EPM_REMOTE_CLONE) {
		/* TODO */
		if (!list_empty(&task->ptraced))
			err = -EBUSY;
	}

	return err;
}

static int export_bts(struct epm_action *action,
		      ghost_t *ghost, struct task_struct *task)
{
	int err = 0;

#ifdef CONFIG_X86_PTRACE_BTS
	/* TODO */
	if (task->bts)
		err = -EBUSY;
#endif

	return err;
}

static int export_pids(struct epm_action *action,
		       ghost_t *ghost, struct task_struct *task)
{
	enum pid_type type, max_type;
	struct pid_link *link;
	int retval = 0; /* Prevent gcc from warning */

#ifdef CONFIG_KRG_SCHED
	retval = export_process_set_links_start(action, ghost, task);
	if (retval)
		goto out;
#endif /* CONFIG_KRG_SCHED */

	if ((action->type == EPM_REMOTE_CLONE
	     && (action->remote_clone.clone_flags & CLONE_THREAD))
	    || (action->type != EPM_REMOTE_CLONE && !thread_group_leader(task)))
		max_type = PIDTYPE_PID + 1;
	else
		max_type = PIDTYPE_MAX;

	type = PIDTYPE_PID;
	if (action->type == EPM_REMOTE_CLONE)
		type++;

	for (; type < max_type; type++) {
		if (type == PIDTYPE_PID)
			link = &task->pids[type];
		else
			link = &task->group_leader->pids[type];

		retval = export_pid(action, ghost, link);
		if (retval)
			goto err;
#ifdef CONFIG_KRG_SCHED
		retval = export_process_set_links(action, ghost,
						  link->pid, type);
		if (retval)
			goto err;
#endif /* CONFIG_KRG_SCHED */
	}

out:
	return retval;

err:
#ifdef CONFIG_KRG_SCHED
	export_process_set_links_end(action, ghost, task);
#endif
	goto out;
}

static void post_export_pids(struct epm_action *action,
			     ghost_t *ghost, struct task_struct *task)
{
#ifdef CONFIG_KRG_SCHED
	export_process_set_links_end(action, ghost, task);
#endif
}

/* export_vfork_done() is located in kerrighed/epm/remote_clone.c */

static int export_cpu_timers(struct epm_action *action,
			     ghost_t *ghost, struct task_struct *task)
{
	int err = 0;

	/* TODO */
	if (action->type != EPM_REMOTE_CLONE) {
		if (!list_empty(&task->cpu_timers[0])
		    || !list_empty(&task->cpu_timers[1])
		    || !list_empty(&task->cpu_timers[2]))
			err = -EBUSY;
	}

	return err;
}

/* export_cred() is located in kerrighed/proc/remote_cred.c */

#ifdef CONFIG_KRG_IPC
/* export_sysv_sem() is located in kerrighed/ipc/mobility.c */
#endif /* !CONFIG_KRG_IPC */

/* export_thread_struct() is located in <arch>/kerrighed/ghost.c */

/* export_fs_struct() is located in kerrighed/fs/mobility.c */

/* export_files_struct() is located in kerrighed/fs/mobility.c */

static int export_uts_namespace(struct epm_action *action,
				ghost_t *ghost, struct task_struct *task)
{
	int err = 0;

	if (task->nsproxy->uts_ns != task->nsproxy->krg_ns->root_nsproxy.uts_ns)
		/* UTS namespace sharing is not implemented yet */
		err = -EPERM;

	return err;
}

static int export_net_namespace(struct epm_action *action,
				ghost_t *ghost, struct task_struct *task)
{
	int err = 0;

	if (task->nsproxy->net_ns != task->nsproxy->krg_ns->root_nsproxy.net_ns)
		/* Net namespace sharing is not implemented yet */
		err = -EPERM;

	return err;
}

static int export_nsproxy(struct epm_action *action,
			  ghost_t *ghost, struct task_struct *task)
{
	int retval;

	BUG_ON(!task->nsproxy->krg_ns);

	retval = export_uts_namespace(action, ghost, task);
	if (retval)
		goto out;
	retval = export_ipc_namespace(action, ghost, task);
	if (retval)
		goto out;
	retval = export_mnt_namespace(action, ghost, task);
	if (retval)
		goto out;
	retval = export_pid_namespace(action, ghost, task);
	if (retval)
		goto out;
	retval = export_net_namespace(action, ghost, task);

out:
	return retval;
}

/* export_signal_struct() is located in kerrighed/epm/signal.c */

/* export_sighand_struct() is located in kerrighed/epm/sighand.c */

/* export_private_signals() is located in kerrighed/epm/signal.c */

static int export_notifier(struct epm_action *action,
			   ghost_t *ghost, struct task_struct *task)
{
	int err = 0;

	if (action->type != EPM_REMOTE_CLONE) {
		/* TODO */
		if (task->notifier)
			err = -EBUSY;
	}

	return err;
}

/* export_audit_context() is located in kernel/auditsc.c */

static int export_exec_ids(struct epm_action *action,
			   ghost_t *ghost, struct task_struct *task)
{
	return 0;
}

static int export_rt_mutexes(struct epm_action *action,
			     ghost_t *ghost, struct task_struct *task)
{
	int err = 0;

#ifdef CONFIG_RT_MUTEXES
	if (action->type != EPM_REMOTE_CLONE) {
		/* TODO */
		if (!plist_head_empty(&task->pi_waiters) || task->pi_blocked_on)
			err = -EBUSY;
	}
#endif

	return err;
}

static int export_io_context(struct epm_action *action,
			     ghost_t *ghost, struct task_struct *task)
{
#ifdef CONFIG_BLOCK
	struct io_context *ioc = task->io_context;

	if (!ioc)
		return 0;

	return ghost_write(ghost, &ioc->ioprio, sizeof(ioc->ioprio));
#else
	return 0;
#endif
}

static int export_last_siginfo(struct epm_action *action,
			       ghost_t *ghost, struct task_struct *task)
{
	int err = 0;

	if (action->type != EPM_REMOTE_CLONE) {
		/* TODO (ptrace) */
		if (task->last_siginfo)
			err = -EBUSY;
	}

	return err;
}

/* export_cgroups() is located in kernel/cgroup.c */

static int export_pi_state(struct epm_action *action,
			   ghost_t *ghost, struct task_struct *task)
{
	int err = 0;

#ifdef CONFIG_FUTEX
	if (!list_empty(&task->pi_state_list))
		err = -EBUSY;
#endif

	return err;
}

static int export_mempolicy(struct epm_action *action,
			    ghost_t *ghost, struct task_struct *task)
{
	int err = 0;

#ifdef CONFIG_NUMA
	if (task->mempolicy)
		err = -EBUSY;
#endif

	return err;
}

static int export_delays(struct epm_action *action,
			 ghost_t *ghost, struct task_struct *task)
{
	int err = 0;

#ifdef CONFIG_TASK_DELAY_ACCT
	if (action->type != EPM_REMOTE_CLONE && task->delays)
		err = ghost_write(ghost, task->delays, sizeof(*task->delays));
#endif

	return err;
}

static int export_krg_structs(struct epm_action *action,
			      ghost_t *ghost, struct task_struct *task)
{
	int retval = 0;

	if (action->type == EPM_MIGRATE) {
		/*
		 * The task kddm object must be linked to at most one task in
		 * the cluster, and after import_krg_structs() it will be
		 * linked to the migrated task.
		 * Unlink and let import_krg_structs() proceed.
		 *
		 * Now that pids are globalized, remote procfs can see that task
		 * even without a link to its task kddm object.
		 */
		krg_task_unlink(task->task_obj, 1);
		retval = ghost_write(ghost, &retval, sizeof(retval));
	}

	return retval;
}

/**
 *  Export a process task struct.
 *  @author  Renaud Lottiaux, Geoffroy Vallée
 *
 *  @param action	Descriptor of the type of export.
 *  @param ghost	Ghost where file data should be stored.
 *  @param task		Task to export file data from.
 *  @param l_regs	Registers of the task to export.
 *
 *  @return		0 if everything ok.
 *			Negative value otherwise.
 */
static int export_task(struct epm_action *action,
		       ghost_t *ghost,
		       struct task_struct *task,
		       struct pt_regs *l_regs)
{
	int r;

#define GOTO_ERROR goto ERROR_LABEL
#define ERROR_LABEL error

	BUG_ON(task->journal_info);

	/* Check against what we cannot manage right now */
	if ((r = export_preempt_notifiers(action, ghost, task))
	    || (r = export_ptraced(action, ghost, task))
	    || (r = export_bts(action, ghost, task))
	    || (r = export_cpu_timers(action, ghost, task))
	    || (r = export_notifier(action, ghost, task))
	    || (r = export_rt_mutexes(action, ghost, task))
	    || (r = export_last_siginfo(action, ghost, task))
	    || (r = export_pi_state(action, ghost, task))
	    || (r = export_mempolicy(action, ghost, task)))
		GOTO_ERROR;

#ifndef CONFIG_KRG_IPC
	if (task->sysvsem.undo_list) {
		r = -EBUSY;
		GOTO_ERROR;
	}
#endif

	/* Export the task struct, and registers */
	prepare_to_export(task);
	r = ghost_write(ghost, task, sizeof(*task));
	if (r)
		GOTO_ERROR;
	r = ghost_write(ghost, l_regs, sizeof(*l_regs));
	if (r)
		GOTO_ERROR;

	r = export_thread_info(action, ghost, task);
	if (r)
		GOTO_ERROR;

	r = export_nsproxy(action, ghost, task);
	if (r)
		GOTO_ERROR;

	r = export_pids(action, ghost, task);
	if (r)
		GOTO_ERROR;

#undef ERROR_LABEL
#define ERROR_LABEL error_pids

	r = export_group_leader(action, ghost, task);
	if (r)
		GOTO_ERROR;

#ifdef CONFIG_KRG_SCHED
	r = export_krg_sched_info(action, ghost, task);
	if (r)
		GOTO_ERROR;
#endif

	r = export_sched_info(action, ghost, task);
	if (r)
		GOTO_ERROR;
#ifdef CONFIG_KRG_MM
	r = export_mm_struct(action, ghost, task);
	if (r)
		GOTO_ERROR;
#endif

	r = export_binfmt(action, ghost, task);
	if (r)
		GOTO_ERROR;

	r = export_vfork_done(action, ghost, task);
	if (r)
		GOTO_ERROR;

	r = export_cred(action, ghost, task);
	if (r)
		GOTO_ERROR;

	r = export_audit_context(action, ghost, task);
	if (r)
		GOTO_ERROR;

	r = export_thread_struct(action, ghost, task);
	if (r)
		GOTO_ERROR;

#ifdef CONFIG_KRG_DVFS
	r = export_fs_struct(action, ghost, task);
	if (r)
		GOTO_ERROR;
	r = export_files_struct(action, ghost, task);
	if (r)
		GOTO_ERROR;
#endif

	r = export_cgroups(action, ghost, task);
	if (r)
		GOTO_ERROR;

	r = export_sched(action,ghost, task);
	if (r)
		GOTO_ERROR;

	r = export_children(action, ghost, task);
	if (r)
		GOTO_ERROR;
	r = export_krg_structs(action, ghost, task);
	if (r)
		GOTO_ERROR;
	r = export_kddm_info_struct(action, ghost, task);
	if (r)
		GOTO_ERROR;

	r = export_private_signals(action, ghost, task);
	if (r)
		GOTO_ERROR;
	r = export_signal_struct(action, ghost, task);
	if (r)
		GOTO_ERROR;
	r = export_sighand_struct(action, ghost, task);
	if (r)
		GOTO_ERROR;

#ifdef CONFIG_KRG_IPC
	r = export_sysv_sem(action, ghost, task);
	if (r)
		GOTO_ERROR;
#endif

	r = export_delays(action, ghost, task);
	if (r)
		GOTO_ERROR;

	r = export_exec_ids(action, ghost, task);
	if (r)
		GOTO_ERROR;

	r = export_io_context(action, ghost, task);
	if (r)
		GOTO_ERROR;

#undef ERROR_LABEL
#undef GOTO_ERROR

error:
	return r;

error_pids:
	post_export_pids(action, ghost, task);
	goto error;
}

static void post_export_task(struct epm_action *action,
			     ghost_t *ghost,
			     struct task_struct *task)
{
	post_export_pids(action, ghost, task);
}

int export_process(struct epm_action *action,
		   ghost_t *ghost,
		   struct task_struct *task,
		   struct pt_regs *regs)
{
	int r;

	r = export_task(action, ghost, task, regs);
	if (r)
		goto error;

	r = export_application(action, ghost, task);
	if (r)
		goto error_app;

error:
	return r;

error_app:
	post_export_task(action, ghost, task);
	goto error;
}

void post_export_process(struct epm_action *action,
			 ghost_t *ghost,
			 struct task_struct *task)
{
	post_export_task(action, ghost, task);
}

/* Unimport */

/* Regular helpers */

static void unimport_krg_structs(struct epm_action  *action,
				 struct task_struct *task)
{
	switch (action->type) {
	case EPM_REMOTE_CLONE:
	case EPM_RESTART:
		__krg_task_free(task);
		break;
	default:
		break;
	}
}

static void unimport_delays(struct task_struct *task)
{
	delayacct_tsk_free(task);
}

static void unimport_mempolicy(struct task_struct *task)
{
	/* TODO */
}

static void unimport_pi_state(struct task_struct *task)
{
	/* TODO */
}

/* unimport_cgroups() is located in kernel/cgroup.c */

static void unimport_last_siginfo(struct task_struct *task)
{
	/* TODO (ptrace) */
}

static void unimport_io_context(struct task_struct *task)
{
	put_io_context(task->io_context);
}

static void unimport_rt_mutexes(struct task_struct *task)
{
	/* TODO */
}

static void unimport_exec_ids(struct task_struct *task)
{
}

/* unimport_audit_context() is located in kernel/auditsc.c */

static void unimport_notifier(struct task_struct *task)
{
	/* TODO */
}

/* unimport_private_signals() is located in kerrighed/epm/signal.c */

/* unimport_sighand_struct() is located in kerrighed/epm/sighand.c */

/* unimport_signal_struct() is located in kerrighed/epm/signal.c */

static void unimport_nsproxy(struct task_struct *task)
{
	put_nsproxy(task->nsproxy);
}

/* unimport_files_struct() is located in kerrighed/fs/mobility.c */

/* unimport_fs_struct() is located in kerrighed/fs/mobility.c */

/* unimport_thread_struct() is located in <arch>/kerrighed/ghost.c */

/* unimport_sysv_sem() is located in kerrighed/ipc/mobility.c */

/* unimport_cred() is located in kerrighed/proc/remote_cred.c */

static void unimport_cpu_timers(struct task_struct *task)
{
	/* TODO */
}

/* unimport_vfork_done() is located in kerrighed/epm/remote_clone.c */

static void __unimport_pids(struct task_struct *task, enum pid_type max_type)
{
	enum pid_type type;

	for (type = 0; type < max_type; type++)
		unimport_pid(&task->pids[type]);
}

static void unimport_pids(struct task_struct *task)
{
	__unimport_pids(task, task->pid == task->tgid ? PIDTYPE_MAX :
							PIDTYPE_PID + 1);
}

static void unimport_bts(struct task_struct *task)
{
#ifdef CONFIG_X86_PTRACE_BTS
	/* TODO */
#endif
}

static
void unimport_ptraced(struct task_struct *task)
{
	/* TODO */
}

static
void unimport_group_leader(struct task_struct *task)
{
	/* Nothing to do... */
}

static
void unimport_children(struct epm_action *action, struct task_struct *task)
{
	switch (action->type) {
	case EPM_REMOTE_CLONE:
	case EPM_RESTART:
		__krg_children_writelock(task);
		krg_children_exit(task);
		break;
	default:
		break;
	}
}

static void unimport_binfmt(struct task_struct *task)
{
	/* Nothing to do... */
}

/* unimport_mm() is located in kerrighed/mm/mobility.c */

static void unimport_sched_info(struct task_struct *task)
{
	/* Nothing to do... */
}

static void unimport_preempt_notifiers(struct task_struct *task)
{
#ifdef CONFIG_PREEMPT_NOTIFIERS
	/* TODO */
#endif
}

/* unimport_sched() is located in kernel/sched.c */

/* unimport_thread_info() is located in <arch>/kerrighed/ghost.c */

/* No arch helpers */

static void unimport_task(struct epm_action *action,
			  struct task_struct *ghost_task)
{
	unimport_io_context(ghost_task);
	unimport_exec_ids(ghost_task);
	unimport_delays(ghost_task);
#ifdef CONFIG_KRG_IPC
	unimport_sysv_sem(ghost_task);
#endif
	unimport_sighand_struct(ghost_task);
	unimport_signal_struct(ghost_task);
	unimport_private_signals(ghost_task);
	unimport_kddm_info_struct(ghost_task);
	unimport_krg_structs(action, ghost_task);
	unimport_children(action, ghost_task);
	unimport_sched(ghost_task);
	unimport_cgroups(ghost_task);
#ifdef CONFIG_KRG_DVFS
	unimport_files_struct(ghost_task);
	unimport_fs_struct(ghost_task);
#endif
	unimport_thread_struct(ghost_task);
	unimport_audit_context(ghost_task);
	unimport_cred(ghost_task);
	unimport_binfmt(ghost_task);
#ifdef CONFIG_KRG_MM
	unimport_mm_struct(ghost_task);
#endif
	unimport_sched_info(ghost_task);
#ifdef CONFIG_KRG_SCHED
	unimport_krg_sched_info(ghost_task);
#endif
	unimport_group_leader(ghost_task);
	unimport_pids(ghost_task);
	unimport_nsproxy(ghost_task);
	unimport_thread_info(ghost_task);
	free_task_struct(ghost_task);

	/* No-op calls, here for symmetry */
	unimport_mempolicy(NULL);
	unimport_pi_state(NULL);
	unimport_last_siginfo(NULL);
	unimport_rt_mutexes(NULL);
	unimport_notifier(NULL);
	unimport_cpu_timers(NULL);
	unimport_bts(NULL);
	unimport_ptraced(NULL);
	unimport_preempt_notifiers(NULL);
}

/* TODO unimport_process() */

/* Import */

/* Arch helpers */

struct exec_domain *import_exec_domain(struct epm_action *action,
				       ghost_t *ghost)
{
	return &default_exec_domain;
}

int import_restart_block(struct epm_action *action,
			 ghost_t *ghost, struct restart_block *p)
{
	enum krgsyms_val fn_id;
	int r;

	r = ghost_read(ghost, &fn_id, sizeof(fn_id));
	if (r)
		goto err_read;
	r = ghost_read(ghost, p, sizeof(*p));
	if (r)
		goto err_read;
	p->fn = krgsyms_import(fn_id);

err_read:
	return r;
}

/* Regular helpers */

/* import_thread_info() is located in <arch>/kerrighed/ghost.c */

/* import_sched() is located in kernel/sched.c */

static int import_preempt_notifiers(struct epm_action *action,
				    ghost_t *ghost, struct task_struct *task)
{
#ifdef CONFIG_PREEMPT_NOTIFIERS
	/* TODO */
#endif
	return 0;
}

static int import_sched_info(struct epm_action *action,
			     ghost_t *ghost, struct task_struct *task)
{
#if defined(CONFIG_SCHEDSTATS) || defined(CONFIG_TASK_DELAY_ACCT)
	task->sched_info.pcount = 0;
#endif
	return 0;
}

/* import_mm() is located in kerrighed/mm/mobility.c */

static int import_binfmt(struct epm_action *action,
			 ghost_t *ghost, struct task_struct *task)
{
	int binfmt_id;
	int err;

	err = ghost_read(ghost, &binfmt_id, sizeof(int));
	if (err)
		goto out;
	task->binfmt = krgsyms_import(binfmt_id);
out:
	return err;
}

static int import_children(struct epm_action *action,
			   ghost_t *ghost, struct task_struct *task)
{
	int r = 0;

	switch (action->type) {
	case EPM_MIGRATE:
		task->children_obj = __krg_children_readlock(task);
		BUG_ON(!task->children_obj);
		krg_children_unlock(task->children_obj);
		break;

	case EPM_REMOTE_CLONE:
	case EPM_RESTART:
		/*
		 * C/R: children are restored later in
		 * app_restart.c:local_restore_children_objects()
		 */
		if (thread_group_leader(task)) {
			task->children_obj = krg_children_alloc(task);
		} else {
			task->children_obj = __krg_children_writelock(task);
			BUG_ON(!task->children_obj);
			__krg_children_share(task);
			krg_children_unlock(task->children_obj);
		}
		if (!task->children_obj)
			r = -ENOMEM;
		break;

	default:
		break;
	}

	return r;
}

static int import_group_leader(struct epm_action *action,
			       ghost_t *ghost, struct task_struct *task)
{
	struct task_struct *leader = task;
	pid_t tgid;
	int err = 0;

	/*
	 * import_pids() set task->tgid to task->pid for a group leader, and 0
	 * otherwise.
	 */
	if (task->pid != task->tgid) {
		BUG_ON(action->type != EPM_RESTART);

		err = ghost_read(ghost, &tgid, sizeof(tgid));
		if (err)
			goto out;

		leader = find_task_by_kpid(tgid);
		BUG_ON(!leader);
		task->tgid = leader->pid;
	}

	task->group_leader = leader;

out:
	return err;
}

static int import_ptraced(struct epm_action *action,
			  ghost_t *ghost, struct task_struct *task)
{
	/* TODO */
	return 0;
}

static int import_bts(struct epm_action *action,
		      ghost_t *ghost, struct task_struct *task)
{
#ifdef CONFIG_X86_PTRACE_BTS
	/* TODO */
#endif
	return 0;
}

static int import_pids(struct epm_action *action,
		       ghost_t *ghost, struct task_struct *task)
{
	enum pid_type type, max_type;
	bool leader;
	int retval = 0;

	leader = !((action->type == EPM_REMOTE_CLONE
		    && (action->remote_clone.clone_flags & CLONE_THREAD))
		   || (action->type != EPM_REMOTE_CLONE
		       && task->pid != task->tgid));
	if (!leader)
		max_type = PIDTYPE_PID + 1;
	else
		max_type = PIDTYPE_MAX;

	type = PIDTYPE_PID;
	if (action->type == EPM_REMOTE_CLONE) {
		struct pid *pid = alloc_pid(task->nsproxy->pid_ns);
		if (!pid) {
			retval = -ENOMEM;
			goto out;
		} else {
			task->pids[PIDTYPE_PID].pid = pid;
		}

		type++;
	}

	for (; type < max_type; type++) {
		retval = import_pid(action, ghost, &task->pids[type], type);
		if (retval) {
			__unimport_pids(task, type);
			break;
		}

#ifdef CONFIG_KRG_SCHED
		retval = import_process_set_links(action, ghost,
						  task->pids[type].pid, type);
		if (retval) {
			__unimport_pids(task, type + 1);
			break;
		}
#endif /* CONFIG_KRG_SCHED */
	}

	task->pid = pid_nr(task_pid(task));
	/*
	 * Marker for import_group_leader(), and unimport_pids() whenever
	 * import_group_leader() fails.
	 */
	task->tgid = leader ? task->pid : 0;

out:
	return retval;
}

/* import_vfork_done() is located in kerrighed/epm/remote_clone.c */

static int import_cpu_timers(struct epm_action *action,
			     ghost_t *ghost, struct task_struct *task)
{
	/* TODO */
	return 0;
}

/* import_cred() is located in kerrighed/proc/remote_cred.c */

/* import_sysv_sem() is located in kerrighed/ipc/mobility.c */

/* import_thread_struct() is located in <arch>/kerrighed/ghost.c */

/* import_fs_struct() is located in kerrighed/fs/mobility.c */

/* import_files_struct() is located in kerrighed/fs/mobility.c */

static int import_uts_namespace(struct epm_action *action,
				ghost_t *ghost, struct task_struct *task)
{
	struct uts_namespace *ns = task->nsproxy->krg_ns->root_nsproxy.uts_ns;

	get_uts_ns(ns);
	task->nsproxy->uts_ns = ns;

	return 0;
}

static int import_net_namespace(struct epm_action *action,
				ghost_t *ghost, struct task_struct *task)
{
	struct net *ns = task->nsproxy->krg_ns->root_nsproxy.net_ns;

	get_net(ns);
	task->nsproxy->net_ns = ns;

	return 0;
}

static int import_nsproxy(struct epm_action *action,
			  ghost_t *ghost, struct task_struct *task)
{
	struct nsproxy *ns;
	int retval = -ENOMEM;

	ns = kmem_cache_zalloc(nsproxy_cachep, GFP_KERNEL);
	task->nsproxy = ns;
	if (!ns)
		goto out;

	atomic_set(&ns->count, 1);

	ns->krg_ns = find_get_krg_ns();

	retval = import_uts_namespace(action, ghost, task);
	if (retval)
		goto err;
	retval = import_ipc_namespace(action, ghost, task);
	if (retval)
		goto err;
	retval = import_mnt_namespace(action, ghost, task);
	if (retval)
		goto err;
	retval = import_pid_namespace(action, ghost, task);
	if (retval)
		goto err;
	retval = import_net_namespace(action, ghost, task);
	if (retval)
		goto err;

out:
	return retval;

err:
	if (!ns->net_ns)
		ns->net_ns = get_net(&init_net);
	free_nsproxy(ns);
	goto out;
}

/* import_signal_struct() is located in kerrighed/epm/signal.c */

/* import_sighand_struct() is located in kerrighed/epm/sighand.c */

/* import_private_signals() is located in kerrighed/epm/signal.c */

static int import_notifier(struct epm_action *action,
			   ghost_t *ghost, struct task_struct *task)
{
	/* TODO */
	return 0;
}

/* import_audit_context() is located in kernel/auditsc.c */

static int import_exec_ids(struct epm_action *action,
			   ghost_t *ghost, struct task_struct *task)
{
	if (action->type == EPM_REMOTE_CLONE
	    && !(action->remote_clone.clone_flags & (CLONE_PARENT|CLONE_THREAD)))
		task->parent_exec_id = task->self_exec_id;
	return 0;
}

static int import_rt_mutexes(struct epm_action *action,
			     ghost_t *ghost, struct task_struct *task)
{
	/* TODO */
	return 0;
}

static int import_io_context(struct epm_action *action,
			     ghost_t *ghost, struct task_struct *task)
{
#ifdef CONFIG_BLOCK
	struct io_context *ioc;
	unsigned short ioprio;
	int err;

	if (!task->io_context)
		return 0;

	err = ghost_read(ghost, &ioprio, sizeof(ioprio));
	if (err)
		return err;

	if (!ioprio_valid(ioprio)) {
		task->io_context = NULL;
		return 0;
	}

	ioc = alloc_io_context(GFP_KERNEL, -1);
	if (!ioc)
		return -ENOMEM;
	ioc->ioprio = ioprio;

	task->io_context = ioc;
#endif

	return 0;
}

static int import_last_siginfo(struct epm_action *action,
			       ghost_t *ghost, struct task_struct *task)
{
	/* TODO (ptrace) */
	return 0;
}

/* import_cgroups() is located in kernel/cgroup.c */

static int import_pi_state(struct epm_action *action,
			   ghost_t *ghost, struct task_struct *task)
{
	/* TODO */
	return 0;
}

static int import_mempolicy(struct epm_action *action,
			    ghost_t *ghost, struct task_struct *task)
{
	/* TODO */
	return 0;
}

static int import_delays(struct epm_action *action,
			 ghost_t *ghost, struct task_struct *task)
{
	int err = 0;
#ifdef CONFIG_TASK_DELAY_ACCT
	struct task_delay_info *delays;

	if (!task->delays || action->type == EPM_REMOTE_CLONE) {
		delayacct_tsk_init(task);
		goto out;
	}

	delays = kmem_cache_alloc(delayacct_cache, GFP_KERNEL);
	if (!delays) {
		err = -ENOMEM;
		goto out;
	}

	err = ghost_read(ghost, delays, sizeof(*delays));
	if (err) {
		kmem_cache_free(delayacct_cache, delays);
		goto out;
	}
	spin_lock_init(&delays->lock);

	task->delays = delays;

out:
#endif

	return err;
}

static int import_krg_structs(struct epm_action *action,
			      ghost_t *ghost, struct task_struct *tsk)
{
	struct task_struct *reaper;
	/* Inits are only needed to prevent compiler warnings. */
	pid_t parent_pid = 0, real_parent_pid = 0, real_parent_tgid = 0;
	pid_t group_leader_pid = 0;
	struct task_kddm_object *obj;
	int retval = 0, dummy;

	if (action->type == EPM_MIGRATE) {
		/* Synchronize with export_krg_structs() */
		retval = ghost_read(ghost, &dummy, sizeof(dummy));
		if (retval)
			goto out;
	}

	/* Initialization of the shared part of the task_struct */

	if (action->type == EPM_REMOTE_CLONE) {
		if (action->remote_clone.clone_flags & CLONE_THREAD) {
			struct task_kddm_object *item;

			item = krg_task_readlock(action->remote_clone.from_pid);
			BUG_ON(!item);
			parent_pid = item->parent;
			real_parent_pid = item->real_parent;
			real_parent_tgid = item->real_parent_tgid;
			BUG_ON(item->group_leader != action->remote_clone.from_tgid);
			krg_task_unlock(action->remote_clone.from_pid);

			group_leader_pid = action->remote_clone.from_tgid;
		} else {
			parent_pid = action->remote_clone.from_pid;
			real_parent_pid = action->remote_clone.from_pid;
			real_parent_tgid = action->remote_clone.from_tgid;
			group_leader_pid = task_tgid_knr(tsk);
		}
	}

	/*
	 * Not a simple write lock because with REMOTE_CLONE and CHECKPOINT the
	 * task container object does not exist yet.
	 */
	obj = krg_task_create_writelock(task_pid_knr(tsk));
	BUG_ON(!obj);

	switch (action->type) {
	case EPM_REMOTE_CLONE:
		obj->parent = parent_pid;
		obj->real_parent = real_parent_pid;
		obj->real_parent_tgid = real_parent_tgid;
		obj->group_leader = group_leader_pid;
		break;
	case EPM_MIGRATE:
		break;
	case EPM_RESTART:
		/*
		 * Initialization of the (real) parent pid and real parent
		 * tgid in case of restart
		 */
		/*
		 * Bringing restarted processes to foreground will need more
		 * work
		 */
		read_lock(&tasklist_lock);
		reaper = task_active_pid_ns(tsk)->child_reaper;
		obj->parent = task_pid_knr(reaper);
		obj->real_parent = obj->parent;
		obj->real_parent_tgid = task_tgid_knr(reaper);
		read_unlock(&tasklist_lock);
		/*
		 * obj->group_leader has already been set when creating the
		 * object. Fix it for non leader threads.
		 */
		obj->group_leader = task_tgid_knr(tsk);
		break;
	default:
		BUG();
	}

	krg_task_unlock(obj->pid);

out:
	return retval;
}

/**
 *  Import a process task struct.
 *  @author  Renaud Lottiaux, Geoffroy Vallée
 *
 *  @param action	Descriptor of the type of import.
 *  @param ghost	Ghost where file data should be stored.
 *  @param l_regs	Registers of the task to imported task.
 *
 *  @return		The task struct of the imported process.
 *			Error code otherwise.
 */
static struct task_struct *import_task(struct epm_action *action,
				       ghost_t *ghost,
				       struct pt_regs *l_regs)
{
	struct task_struct *task;
	int retval;

	/* No-op calls, here for symmetry */
	BUG_ON(import_preempt_notifiers(action, ghost, NULL)
	       || import_ptraced(action, ghost, NULL)
	       || import_bts(action, ghost, NULL)
	       || import_cpu_timers(action, ghost, NULL)
	       || import_notifier(action, ghost, NULL)
	       || import_rt_mutexes(action, ghost, NULL)
	       || import_last_siginfo(action, ghost, NULL)
	       || import_pi_state(action, ghost, NULL)
	       || import_mempolicy(action, ghost, NULL));

	/* Import the task struct, and registers */
	task = alloc_task_struct();
	if (!task) {
		retval = -ENOMEM;
		goto err_alloc_task;
	}

	retval = ghost_read(ghost, task, sizeof(struct task_struct));
	if (retval)
		goto err_task;
	retval = ghost_read(ghost, l_regs, sizeof(struct pt_regs));
	if (retval)
		goto err_regs;

	/*
	 * Init fields. Paranoia to avoid dereferencing a pointer which has no
	 * meaning on this node.
	 */
	atomic_set(&task->usage, 2);
#ifdef CONFIG_PREEMPT_NOTIFIERS
	INIT_HLIST_HEAD(&task->preempt_notifiers);
#endif
	INIT_LIST_HEAD(&task->tasks);
	INIT_LIST_HEAD(&task->ptraced);
	INIT_LIST_HEAD(&task->ptrace_entry);
	task->real_parent = NULL;
	task->parent = NULL;
	INIT_LIST_HEAD(&task->children);
	INIT_LIST_HEAD(&task->sibling);
	task->group_leader = NULL;
	INIT_LIST_HEAD(&task->ptraced);
	INIT_LIST_HEAD(&task->ptrace_entry);
#ifdef CONFIG_X86_PTRACE_BTS
	BUG_ON(task->bts);
	BUG_ON(task->bts_buffer);
#endif
	INIT_LIST_HEAD(&task->thread_group);
	INIT_LIST_HEAD(&task->cpu_timers[0]);
	INIT_LIST_HEAD(&task->cpu_timers[1]);
	INIT_LIST_HEAD(&task->cpu_timers[2]);
	mutex_init(&task->cred_exec_mutex);
#ifndef CONFIG_KRG_IPC
	BUG_ON(task->sysvsem.undo_list);
#endif
	BUG_ON(task->notifier);
	BUG_ON(task->notifier_data);
	task->notifier_mask = NULL;
	spin_lock_init(&task->alloc_lock);
#ifdef CONFIG_GENERIC_HARDIRQS
	BUG_ON(task->irqaction);
#endif
	spin_lock_init(&task->pi_lock);
#ifdef CONFIG_RT_MUTEXES
	plist_head_init(&task->pi_waiters, &task->pi_lock);
	BUG_ON(task->pi_blocked_on);
#endif
#ifdef CONFIG_DEBUG_MUTEXES
	BUG_ON(task->blocked_on); /* not blocked yet */
#endif
	/* Almost copy paste from fork.c for lock debugging stuff, to avoid
	 * fooling this node with traces from the exporting node */
#ifdef CONFIG_TRACE_IRQFLAGS
	task->irq_events = 0;
	task->hardirqs_enabled = 1;
	task->hardirq_enable_ip = _THIS_IP_;
	task->hardirq_enable_event = 0;
	task->hardirq_disable_ip = 0;
	task->hardirq_disable_event = 0;
	task->softirqs_enabled = 1;
	task->softirq_enable_ip = _THIS_IP_;
	task->softirq_enable_event = 0;
	task->softirq_disable_ip = 0;
	task->softirq_disable_event = 0;
	task->hardirq_context = 0;
	task->softirq_context = 0;
#endif
#ifdef CONFIG_LOCKDEP
	task->lockdep_depth = 0; /* no locks held yet */
	task->curr_chain_key = 0;
	task->lockdep_recursion = 0;
#endif
	/* End of lock debugging stuff */
	if (action->type == EPM_RESTART)
		task->journal_info = NULL;
	else
		BUG_ON(task->journal_info);
	BUG_ON(task->bio_list);
	BUG_ON(task->bio_tail);
	BUG_ON(task->reclaim_state);
	if (action->type == EPM_RESTART)
		task->backing_dev_info = NULL;
	else
		BUG_ON(task->backing_dev_info);
	BUG_ON(task->last_siginfo);
#ifdef CONFIG_FUTEX
	INIT_LIST_HEAD(&task->pi_state_list);
	task->pi_state_cache = NULL;
#endif
#ifdef CONFIG_NUMA
	BUG_ON(task->mempolicy);
#endif
	task->splice_pipe = NULL;
	BUG_ON(task->scm_work_list);
#ifdef CONFIG_FUNCTION_GRAPH_TRACER
	task->ret_stack = NULL;
#endif
	task->task_obj = NULL;
	rcu_assign_pointer(task->parent_children_obj, NULL);
	task->children_obj = NULL;
	task->application = NULL;

	/* Now, let's resume importing the process. */

	retval = import_thread_info(action, ghost, task);
	if (retval)
		goto err_thread_info;

	retval = import_nsproxy(action, ghost, task);
	if (retval)
		goto err_nsproxy;

	retval = import_pids(action, ghost, task);
	if (retval)
		goto err_pids;
	retval = import_group_leader(action, ghost, task);
	if (retval)
		goto err_group_leader;

#ifdef CONFIG_KRG_SCHED
	retval = import_krg_sched_info(action, ghost, task);
	if (retval)
		goto err_krg_sched_info;
#endif

	retval = import_sched_info(action, ghost, task);
	if (retval)
		goto err_sched_info;

#ifdef CONFIG_KRG_MM
	retval = import_mm_struct(action, ghost, task);
	if (retval)
		goto err_mm_struct;
#endif

	retval = import_binfmt(action, ghost, task);
	if (retval)
		goto err_binfmt;

	retval = import_vfork_done(action, ghost, task);
	if (retval)
		goto err_vfork_done;

	retval = import_cred(action, ghost, task);
	if (retval)
		goto err_cred;

	retval = import_audit_context(action, ghost, task);
	if (retval)
		goto err_audit_context;

	retval = import_thread_struct(action, ghost, task);
	if (retval)
		goto err_thread_struct;

#ifdef CONFIG_KRG_DVFS
	retval = import_fs_struct(action, ghost, task);
	if (retval)
		goto err_fs_struct;
	retval = import_files_struct(action, ghost, task);
	if (retval)
		goto err_files_struct;
#endif

	retval = import_cgroups(action, ghost, task);
	if (retval)
		goto err_cgroups;

	retval = import_sched(action, ghost, task);
	if (retval)
		goto err_sched;

	retval = import_children(action, ghost, task);
	if (retval)
		goto err_children;
	retval = import_krg_structs(action, ghost, task);
	if (retval)
		goto err_krg_structs;
	retval = import_kddm_info_struct(action, ghost, task);
	if (retval)
		goto err_kddm_info_struct;

	retval = import_private_signals(action, ghost, task);
	if (retval)
		goto err_signals;
	retval = import_signal_struct(action, ghost, task);
	if (retval)
		goto err_signal_struct;

	retval = import_sighand_struct(action, ghost, task);
	if (retval)
		goto err_sighand_struct;

#ifdef CONFIG_KRG_IPC
	retval = import_sysv_sem(action, ghost, task);
	if (retval)
		goto err_sysv_sem;
#endif

	retval = import_delays(action, ghost, task);
	if (retval)
		goto err_delays;

	retval = import_exec_ids(action, ghost, task);
	if (retval)
		goto err_exec_ids;

	retval = import_io_context(action, ghost, task);
	if (retval)
		goto err_io_context;

	return task;

err_io_context:
	unimport_exec_ids(task);
err_exec_ids:
	unimport_delays(task);
err_delays:
#ifdef CONFIG_KRG_IPC
	unimport_sysv_sem(task);
err_sysv_sem:
#endif
	unimport_sighand_struct(task);
err_sighand_struct:
	unimport_signal_struct(task);
err_signal_struct:
	unimport_private_signals(task);
err_signals:
	unimport_kddm_info_struct(task);
err_kddm_info_struct:
	unimport_krg_structs(action, task);
err_krg_structs:
	unimport_children(action, task);
err_children:
	unimport_sched(task);
err_sched:
	unimport_cgroups(task);
err_cgroups:
#ifdef CONFIG_KRG_DVFS
	unimport_files_struct(task);
err_files_struct:
	unimport_fs_struct(task);
err_fs_struct:
#endif
	unimport_thread_struct(task);
err_thread_struct:
	unimport_audit_context(task);
err_audit_context:
	unimport_cred(task);
err_cred:
	unimport_vfork_done(task);
err_vfork_done:
	unimport_binfmt(task);
err_binfmt:
#ifdef CONFIG_KRG_MM
	unimport_mm_struct(task);
err_mm_struct:
#endif
	unimport_sched_info(task);
err_sched_info:
#ifdef CONFIG_KRG_SCHED
	unimport_krg_sched_info(task);
err_krg_sched_info:
#endif
	unimport_group_leader(task);
err_group_leader:
	unimport_pids(task);
err_pids:
	unimport_nsproxy(task);
err_nsproxy:
	unimport_thread_info(task);
err_thread_info:
/*	unimport_regs(task); */
err_regs:
/*	unimport_task_struct(task); */
err_task:
	free_task_struct(task);
err_alloc_task:
	/* No-op calls, here for symmetry */
	unimport_mempolicy(NULL);
	unimport_pi_state(NULL);
	unimport_last_siginfo(NULL);
	unimport_rt_mutexes(NULL);
	unimport_notifier(NULL);
	unimport_cpu_timers(NULL);
	unimport_bts(NULL);
	unimport_ptraced(NULL);
	unimport_preempt_notifiers(NULL);
	return ERR_PTR(retval);
}

/* Ghost release */

static void free_ghost_task(struct task_struct *task)
{
	BUG_ON(!task);
	BUG_ON(!list_empty(&task->sibling));
	BUG_ON(!list_empty(&task->ptrace_entry));
	BUG_ON(!list_empty(&task->thread_group));
	free_task_struct(task);
}

void free_ghost_process(struct task_struct *ghost)
{
#ifdef CONFIG_KRG_MM
	free_ghost_mm(ghost);
#endif

#ifdef CONFIG_KRG_DVFS
	free_ghost_files(ghost);
#endif

	free_ghost_audit_context(ghost);
	free_ghost_cred(ghost);

	free_ghost_cgroups(ghost);
	put_nsproxy(ghost->nsproxy);
	kmem_cache_free(kddm_info_cachep, ghost->kddm_info);

	free_ghost_thread_info(ghost);

	free_ghost_task(ghost);
}

static int register_pids(struct task_struct *task, struct epm_action *action)
{
	enum pid_type type;

	for (type = 0; type < PIDTYPE_MAX; type++) {
		if (!thread_group_leader(task) && type > PIDTYPE_PID)
			break;
		if ((type != PIDTYPE_PID || action->type != EPM_REMOTE_CLONE)
		    && task->pids[type].pid->kddm_obj)
			krg_end_get_pid(task->pids[type].pid);
	}

	return 0;
}

/**
 * This function creates the new process from the ghost process
 * @author Geoffroy Vallée, Louis Rilling
 *
 * @param tskRecv               Pointer on the ghost process
 * @param regs			Pointer on the registers of the ghost process
 * @param action		Migration, checkpoint, creation, etc.
 *
 * @return                      Pointer on the running task
 *                              (created with the ghost process)
 */
static
struct task_struct *create_new_process_from_ghost(struct task_struct *tskRecv,
						  struct pt_regs *l_regs,
						  struct epm_action *action)
{
	struct pid *pid;
	struct task_struct *newTsk;
	struct task_kddm_object *obj;
	unsigned long flags;
	unsigned long stack_start;
	unsigned long stack_size;
	int *parent_tidptr;
	int *child_tidptr;
	struct children_kddm_object *parent_children_obj;
	pid_t real_parent_tgid;
	int retval;

	BUG_ON(!l_regs || !tskRecv);
	BUG_ON(action->type == EPM_CHECKPOINT);

	/*
	 * The active process must be considered as remote until all links
	 * with parent and children are restored atomically.
	 */
	tskRecv->parent = tskRecv->real_parent = baby_sitter;

	/* Re-attach to the children kddm object of the parent. */
	if (action->type == EPM_REMOTE_CLONE) {
		real_parent_tgid = action->remote_clone.from_tgid;
		/* We need writelock to declare the new child later. */
		parent_children_obj = krg_children_writelock(real_parent_tgid);
		BUG_ON(!parent_children_obj);
		krg_children_get(parent_children_obj);
		rcu_assign_pointer(tskRecv->parent_children_obj,
				   parent_children_obj);
	} else {
		pid_t parent, real_parent;

		/*
		 * We must not call krg_parent_children_readlock since we are
		 * restoring here the data needed for this function to work.
		 */
		obj = __krg_task_readlock(tskRecv);
		real_parent_tgid = obj->real_parent_tgid;
		__krg_task_unlock(tskRecv);

		parent_children_obj =
			krg_children_readlock(real_parent_tgid);
		if (!krg_get_parent(parent_children_obj, tskRecv,
				    &parent, &real_parent)) {
			krg_children_get(parent_children_obj);
			rcu_assign_pointer(tskRecv->parent_children_obj,
					   parent_children_obj);
		}
		if (parent_children_obj)
			krg_children_unlock(parent_children_obj);
	}

	flags = (tskRecv->exit_signal & CSIGNAL) | CLONE_VM | CLONE_THREAD
		| CLONE_SIGHAND;
	stack_start = user_stack_pointer(l_regs);
	/*
	 * Will BUG as soon as used in copy_thread (e.g. ia64, but not i386 and
	 * x86_64)
	 */
	stack_size = 0;
	parent_tidptr = NULL;
	child_tidptr = NULL;

	if (action->type == EPM_REMOTE_CLONE) {
		/* Adjust do_fork parameters */

		/*
		 * Do not pollute exit signal of the child with bits from
		 * parent's exit_signal
		 */
		flags &= ~CSIGNAL;
		flags = flags | action->remote_clone.clone_flags;
		stack_start = action->remote_clone.stack_start;
		stack_size = action->remote_clone.stack_size;
		parent_tidptr = action->remote_clone.parent_tidptr;
		child_tidptr = action->remote_clone.child_tidptr;
	}

	pid = task_pid(tskRecv);
	BUG_ON(!pid);

	obj = __krg_task_writelock(tskRecv);

	krg_current = tskRecv;
	newTsk = copy_process(flags, stack_start, l_regs, stack_size,
			      child_tidptr, pid, 0);
	krg_current = NULL;

	if (IS_ERR(newTsk)) {
		__krg_task_unlock(tskRecv);

		if (action->type == EPM_REMOTE_CLONE)
			krg_children_unlock(tskRecv->parent_children_obj);
		krg_children_put(parent_children_obj);

		return newTsk;
	}

	BUG_ON(newTsk->task_obj);
	BUG_ON(obj->task);
	write_lock_irq(&tasklist_lock);
	newTsk->task_obj = obj;
	obj->task = newTsk;
	write_unlock_irq(&tasklist_lock);
	BUG_ON(newTsk->parent_children_obj != tskRecv->parent_children_obj);
	BUG_ON(!newTsk->children_obj);

	BUG_ON(newTsk->exit_signal != (flags & CSIGNAL));
	BUG_ON(action->type == EPM_MIGRATE &&
	       newTsk->exit_signal != tskRecv->exit_signal);

	if (action->type == EPM_RESTART)
		newTsk->exit_signal = tskRecv->exit_signal;

	/* TODO: distributed threads */
	BUG_ON(newTsk->group_leader->pid != newTsk->tgid);
	BUG_ON(newTsk->task_obj->group_leader != task_tgid_knr(newTsk));

	if (action->type == EPM_REMOTE_CLONE) {
		retval = krg_new_child(parent_children_obj,
				       action->remote_clone.from_pid,
				       newTsk);

		krg_children_unlock(parent_children_obj);
		if (retval)
			PANIC("Remote child %d of %d created"
			      " but could not be registered!",
			      task_pid_knr(newTsk),
			      action->remote_clone.from_pid);
	}

	if (action->type == EPM_MIGRATE || action->type == EPM_RESTART)
		newTsk->did_exec = tskRecv->did_exec;

	__krg_task_unlock(tskRecv);

	retval = register_pids(newTsk, action);
	BUG_ON(retval);

	if (action->type == EPM_MIGRATE
	    || action->type == EPM_RESTART) {
		/*
		 * signals should be copied from the ghost, as do_fork does not
		 * clone the signal queue
		 */
		if (!sigisemptyset(&tskRecv->pending.signal)
		    || !list_empty(&tskRecv->pending.list)) {
			unsigned long flags;

			if (!lock_task_sighand(newTsk, &flags))
				BUG();
			list_splice(&tskRecv->pending.list,
				    &newTsk->pending.list);
			sigorsets(&newTsk->pending.signal,
				  &newTsk->pending.signal,
				  &tskRecv->pending.signal);
			unlock_task_sighand(newTsk, &flags);

			init_sigpending(&tskRecv->pending);
		}
		/*
		 * Always set TIF_SIGPENDING, since migration/checkpoint
		 * interrupted the task as an (ignored) signal. This way
		 * interrupted syscalls are transparently restarted.
		 */
		set_tsk_thread_flag(newTsk, TIF_SIGPENDING);
	}

	newTsk->files->next_fd = tskRecv->files->next_fd;

	if (action->type == EPM_MIGRATE
	    || action->type == EPM_RESTART) {
		/* Remember process times until now (cleared by do_fork) */
		newTsk->utime = tskRecv->utime;
		/* stime will be updated later to account for migration time */
		newTsk->stime = tskRecv->stime;
		newTsk->gtime = tskRecv->gtime;
		newTsk->utimescaled = tskRecv->utimescaled;
		newTsk->stimescaled = tskRecv->stimescaled;
		newTsk->prev_utime = tskRecv->prev_utime;
		newTsk->prev_stime = tskRecv->prev_stime;

		/* Restore flags changed by copy_process() */
		newTsk->flags = tskRecv->flags;
	}
	newTsk->flags &= ~PF_STARTING;

	/*
	 * Atomically restore links with local relatives and allow relatives
	 * to consider newTsk as local.
	 * Until now, newTsk is linked to baby sitter and not linked to any
	 * child.
	 */
	join_local_relatives(newTsk);

#ifdef CONFIG_KRG_SCHED
	post_import_krg_sched_info(newTsk);
#endif

	/* Now the process can be made world-wide visible. */
	krg_set_pid_location(newTsk);

	return newTsk;
}

void hide_process(struct task_struct *task)
{
	krg_unset_pid_location(task);

	__krg_task_writelock(task);
	leave_all_relatives(task);
	__krg_task_unlock(task);
}

void unhide_process(struct task_struct *task)
{
	struct task_kddm_object *task_obj;

	task_obj = __krg_task_writelock(task);
	BUG_ON(!task_obj);
	write_lock_irq(&tasklist_lock);
	task_obj->task = task;
	task->task_obj = task_obj;
	write_unlock_irq(&tasklist_lock);
	__krg_task_unlock(task);

	/*
	 * Atomically restore links with local relatives and allow relatives
	 * to consider task as local.
	 * Until now, task is linked to baby sitter and not linked to any child.
	 */
	join_local_relatives(task);

	/* Now the process can be made world-wide visible. */
	krg_set_pid_location(task);
}

struct task_struct *import_process(struct epm_action *action,
				   ghost_t *ghost)
{
	struct task_struct *ghost_task;
	struct task_struct *active_task;
	struct pt_regs regs;
	int err;

	/* Process importation */

	if (action->type == EPM_MIGRATE) {
		/*
		 * Ensure that no task struct survives from a previous stay of
		 * the process on this node.
		 * This can happen if a process comes back very quickly
		 * and before the call to do_exit_wo_notify() ending
		 * the previous migration.
		 */
		struct pid *pid;

		rcu_read_lock();
		pid = find_kpid(action->migrate.pid);
		if (pid) {
			get_pid(pid);
			while (pid_task(pid, PIDTYPE_PID)) {
				rcu_read_unlock();
				schedule();
				rcu_read_lock();
			}
			put_pid(pid);
		}
		rcu_read_unlock();
	}

	ghost_task = import_task(action, ghost, &regs);
	if (IS_ERR(ghost_task)) {
		err = PTR_ERR(ghost_task);
		goto err_task;
	}
	BUG_ON(!ghost_task);

	active_task = create_new_process_from_ghost(ghost_task, &regs, action);
	if (IS_ERR(active_task)) {
		err = PTR_ERR(active_task);
		goto err_active_task;
	}
	BUG_ON(!active_task);

	free_ghost_process(ghost_task);

	err = import_application(action, ghost, active_task);
	if (err)
		goto err_application;

	return active_task;

err_application:
	unimport_application(action, ghost, active_task);
	goto err_task;
err_active_task:
	unimport_task(action, ghost_task);
err_task:
	return ERR_PTR(err);
}
