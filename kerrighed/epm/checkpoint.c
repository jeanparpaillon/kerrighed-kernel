/*
 *  kerrighed/epm/checkpoint.c
 *
 *  Copyright (C) 1999-2008 INRIA, Universite de Rennes 1, EDF
 *  Copyright (C) 2008-2009 Matthieu Fertré - Kerlabs
 */

/**
 *  Process checkpointing.
 *  @file checkpoint.c
 *
 *  @author Geoffroy Vallée, Matthieu Fertré
 */

#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <linux/file.h>
#include <linux/cred.h>
#include <linux/kernel.h>
#include <kerrighed/pid.h>
#include <kerrighed/application.h>
#include <kerrighed/kerrighed_signal.h>
#include <kerrighed/hotplug.h>
#include <kerrighed/action.h>
#include <kerrighed/ghost.h>
#include <kerrighed/ghost_helpers.h>
#include <kerrighed/remote_cred.h>
#include <kerrighed/debug.h>
#include "ghost.h"
#include "epm_internal.h"
#include "checkpoint.h"

/*****************************************************************************/
/*                                                                           */
/*                              TOOLS FUNCTIONS                              */
/*                                                                           */
/*****************************************************************************/

int can_be_checkpointed(struct task_struct *task_to_checkpoint)
{
	struct nsproxy *nsp;

	/* Task must live in the Kerrighed container. */
	rcu_read_lock();
	nsp = rcu_dereference(task_to_checkpoint->nsproxy);
	if (!nsp || !nsp->krg_ns) {
		rcu_read_unlock();
		goto exit;
	}
	rcu_read_unlock();

	/* Check permissions */
	if (!permissions_ok(task_to_checkpoint))
		goto exit;

	/* Check capabilities */
	if (!can_use_krg_cap(task_to_checkpoint, CAP_CHECKPOINTABLE))
		goto exit;

	return 1; /* means true */

exit:
	return 0; /* means false */
}

/*****************************************************************************/
/*                                                                           */
/*                            CHECKPOINT FUNCTIONS                           */
/*                                                                           */
/*****************************************************************************/

/**
 *  This function save the process information in a ghost
 *  @author Geoffroy Vallée, Renaud Lottiaux, Matthieu Fertré
 *
 *  @param task_to_checkpoint	Pointer on the task to checkpoint
 *
 *  @return			0 if everythink ok, negative value otherwise.
 */
static int checkpoint_task_to_ghost(struct epm_action *action,
				    ghost_t *ghost,
				    struct task_struct *task_to_checkpoint,
				    struct pt_regs *regs)
{
	int r = -EINVAL;

	if (task_to_checkpoint == NULL) {
		PANIC("Task to checkpoint is NULL!!\n");
		goto exit;
	}

	if (regs == NULL) {
		PANIC("Regs are NULL!!\n");
		goto exit;
	}

	r = export_process(action, ghost, task_to_checkpoint, regs);
	if (!r)
		post_export_process(action, ghost, task_to_checkpoint);

exit:
	return r;
}

/**
 *  This function saves the process information in a file
 *  @author Geoffroy Vallée, Renaud Lottiaux, Matthieu Fertré
 *
 *  @param task_to_checkpoint	Pointer to the task to checkpoint
 *
 *  @return 0			if everythink ok, negative value otherwise.
 */
static
int checkpoint_task_on_disk(struct epm_action *action,
			    struct task_struct *task_to_checkpoint,
			    struct pt_regs *regs)
{
	ghost_t *ghost;
	int r = -EINVAL;

	struct app_struct *app = task_to_checkpoint->application;
	BUG_ON(!app);

	ghost = get_task_chkpt_ghost(app, task_to_checkpoint);
	if (!ghost) {
		__WARN();
		return r;
	}

	/* Do the process ghosting */
	return checkpoint_task_to_ghost(action, ghost,
				        task_to_checkpoint, regs);
}

/**
 *  This function saves the process information
 *  @author Geoffroy Vallée, Renaud Lottiaux, Matthieu Fertré
 *
 *  @param task_to_checkpoint	Pointer to the task to checkpoint
 *
 *  @return 0			if everythink ok, negative value otherwise.
 */
static int checkpoint_task(struct epm_action *action,
			   struct task_struct *task_to_checkpoint,
			   struct pt_regs *regs)
{
	int r;
	struct app_struct *app = task_to_checkpoint->application;
	ghost_fs_t oldfs;

	BUG_ON(!action);
	BUG_ON(!task_to_checkpoint);
	BUG_ON(!regs);
	BUG_ON(!app);

	r = set_ghost_fs(&oldfs, app->cred->fsuid, app->cred->fsgid);
	if (r)
		goto out;

	/* Do the process ghosting */
	r = checkpoint_task_on_disk(action, task_to_checkpoint, regs);

	unset_ghost_fs(&oldfs);

	if (r)
		ckpt_err(action, r,
			 "Fail to checkpoint process %d",
			 task_pid_knr(task_to_checkpoint));
out:
	return r;
}

/*****************************************************************************/
/*                                                                           */
/*                             REQUEST HELPER FUNCTIONS                      */
/*                                                                           */
/*****************************************************************************/

/* Checkpoint signal handler */
static void krg_task_checkpoint(int sig, struct siginfo *info,
				struct pt_regs *regs)
{
	struct epm_action action;
	int r = 0;

	/* do we really take a checkpoint ? */
	if (si_option(*info) != CHKPT_ONLY_STOP) {
		action.type = EPM_CHECKPOINT;
		action.checkpoint.shared = CR_SAVE_LATER;
		r = checkpoint_task(&action, current, regs);
	}

	set_current_state(TASK_UNINTERRUPTIBLE);

	if (r != 0)
		set_task_result(current, r);
	else
		set_task_result(current, PCUS_OPERATION_OK);

	if (current->state == TASK_UNINTERRUPTIBLE)
		schedule(); /* be sure to stop now! */
}

void register_checkpoint_hooks(void)
{
	hook_register(&krg_handler[KRG_SIG_CHECKPOINT], krg_task_checkpoint);
}
