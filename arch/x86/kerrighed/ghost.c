/*
 *  arch/x86/kerrighed/ghost.c
 *
 *  Copyright (C) 2006-2007 Arkadiusz Danilecki
 *                          Pascal Gallard - Kerlabs, Louis Rilling - Kerlabs
 */

#include <linux/sched.h>
#include <asm/processor.h>
#include <asm/system.h>
#include <asm/uaccess.h>
#include <asm/i387.h>
#include <kerrighed/ghost.h>
#include <kerrighed/ghost_helpers.h>

struct epm_action;

void prepare_to_export(struct task_struct *task)
{
	if (!task->exit_state)
		unlazy_fpu(task);
}

/* struct thread_info */

int export_thread_info(struct epm_action *action,
		       ghost_t *ghost, struct task_struct *task)
{
	int r;

	r = ghost_write(ghost, task->stack, sizeof(struct thread_info));
	if (r)
		goto error;

	r = export_exec_domain(action, ghost, task);
	if (r)
		goto error;
	r = export_restart_block(action, ghost, task);

error:
	return r;
}

static void __free_thread_info(struct thread_info *ti)
{
	ti->task->thread.xstate = NULL;
	free_thread_info(ti);
}

int import_thread_info(struct epm_action *action,
		       ghost_t *ghost, struct task_struct *task)
{
	struct thread_info *p;
	int r;

	p = alloc_thread_info(task);
	if (!p) {
		r = -ENOMEM;
		goto exit;
	}

	r = ghost_read(ghost, p, sizeof(struct thread_info));
	/* Required by [__]free_thread_info() */
	p->task = task;
	if (r)
		goto exit_free_thread_info;

	p->exec_domain = import_exec_domain(action, ghost);

	p->preempt_count = 0;
	p->addr_limit = USER_DS;

	r = import_restart_block(action, ghost, &p->restart_block);
	if (r)
		goto exit_free_thread_info;

	task->stack = p;

exit:
	return r;

exit_free_thread_info:
	__free_thread_info(p);
	goto exit;
}

void unimport_thread_info(struct task_struct *task)
{
	__free_thread_info(task->stack);
}

void free_ghost_thread_info(struct task_struct *ghost)
{
	free_thread_info(ghost->stack);
}

int export_thread_struct(struct epm_action *action,
			 ghost_t *ghost, struct task_struct *tsk)
{
	int r = -EBUSY;

	if (!tsk->exit_state) {
		if (test_tsk_thread_flag(tsk, TIF_IO_BITMAP))
			goto out;
#ifdef CONFIG_X86_DS
		if (test_tsk_thread_flag(tsk, TIF_DS_AREA_MSR))
			goto out;
#endif

#ifdef CONFIG_X86_64
		savesegment(gs, tsk->thread.gsindex);
		savesegment(fs, tsk->thread.fsindex);
		savesegment(es, tsk->thread.es);
		savesegment(ds, tsk->thread.ds);

#else /* CONFIG_X86_32 */
		lazy_save_gs(tsk->thread.gs);

		WARN_ON(tsk->thread.vm86_info);
#endif /* CONFIG_X86_32 */
	}

	r = ghost_write(ghost, &tsk->thread, sizeof (tsk->thread));
	if (r)
		goto out;
	if (tsk->thread.xstate)
		r = ghost_write(ghost, tsk->thread.xstate, xstate_size);

out:
	return r;
}

int import_thread_struct(struct epm_action *action,
			 ghost_t *ghost, struct task_struct *tsk)
{
	int r;

	r = ghost_read(ghost, &tsk->thread, sizeof (tsk->thread));
	if (r)
		goto out;

	/*
	 * Make get_wchan return do_exit for zombies
	 * We only set a marker to let copy_thread() do the right thing.
	 */
	if (tsk->exit_state)
		tsk->thread.sp = ~0UL;
	else
		tsk->thread.sp = 0;

	if (tsk->thread.xstate) {
		r = -ENOMEM;
		tsk->thread.xstate = kmem_cache_alloc(task_xstate_cachep,
						      GFP_KERNEL);
		if (!tsk->thread.xstate)
			goto out;
		r = ghost_read(ghost, tsk->thread.xstate, xstate_size);
		if (r)
			free_thread_xstate(tsk);
	}

out:
	return r;
}

void unimport_thread_struct(struct task_struct *task)
{
	free_thread_xstate(task);
}
