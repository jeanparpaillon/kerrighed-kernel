/*
 *  kerrighed/epm/restart.c
 *
 *  Copyright (C) 1999-2008 INRIA, Universite de Rennes 1, EDF
 *  Copyright (C) 2008-2009 Matthieu Fertré - Kerlabs
 */

/**
 *  Process restart.
 *  @file restart.c
 *
 *  @author Geoffroy Vallée, Matthieu Fertré
 */

#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/pid_namespace.h>
#include <kerrighed/pid.h>
#include <kerrighed/application.h>
#include <kerrighed/action.h>
#include <kerrighed/ghost.h>
#include <kerrighed/ghost_helpers.h>
#include "ghost.h"
#include "pid.h"
#include "restart.h"

/**
 *  Load the process information saved in a checkpoint-file
 *  @author	Geoffroy Vallée, Renaud Lottiaux, Matthieu Fertré
 *
 *  @param action	Restart descriptor
 *  @param pid		Pid of the task to restart
 *  @param ghost	Ghost to restart the task from
 *
 *  @return		New Tasks's UNIX PID if success, NULL if failure
 */
static
struct task_struct *restart_task_from_ghost(struct epm_action *action,
					    pid_t pid,
					    ghost_t *ghost)
{
	struct task_struct *newTsk = NULL;
	int err;

	/* Reserve pid */
	err = reserve_pid(pid);

	if (err) {
		newTsk = ERR_PTR(-E_CR_PIDBUSY);
		goto exit;
	}

	/* Recreate the process */

	newTsk = import_process(action, ghost);
	if (IS_ERR(newTsk))
		goto unimport_process;
	BUG_ON(!newTsk);

	/* Link pid kddm object and task kddm obj */
	err = krg_pid_link_task(pid);
	if (err) {
		newTsk = ERR_PTR(err);
		goto exit;
	}

exit:
	return newTsk;

unimport_process:
/*
 * WARNING: we must free the pid if it has been successfully reserved
 */
	printk("must free the pid\n");
	goto exit;
}

/**
 *  Load the process information saved in a checkpoint-file
 *  @author       Matthieu Fertré
 *
 *  @param action	Restart descriptor
 *  @param pid		Pid of the task to restart
 *  @param app_id	Application id
 *  @param chkpt_sn	Sequence number of the checkpoint
 *
 *  @return		New task if success, PTR_ERR if failure
 */
static
struct task_struct *restart_task_from_disk(struct epm_action *action,
					   pid_t pid,
					   long app_id,
					   int chkpt_sn)
{
	ghost_t *ghost;
	struct task_struct *task;

	ghost = create_file_ghost(GHOST_READ, app_id, chkpt_sn,
				  "task_%d.bin", pid);

	if (IS_ERR(ghost))
		return ERR_PTR(PTR_ERR(ghost));

	/* Recreate the process */

	task = restart_task_from_ghost(action, pid, ghost);

	ghost_close(ghost);

	return task;
}

/**
 *  Load the process information saved
 *  @author      Matthieu Fertré
 *
 *  @param action	Restart descriptor
 *  @param pid		Pid of the task to restart
 *  @param app_id	Application id
 *  @param chkpt_sn	Sequence number of the checkpoint
 *
 *  @return		New task if success, PTR_ERR if failure
 */
static
struct task_struct *restart_task(struct epm_action *action,
				 pid_t pid, long app_id,
				 int chkpt_sn)
{
	struct task_struct *task = NULL;
	ghost_fs_t oldfs;

	__set_ghost_fs(&oldfs);

	task = restart_task_from_disk(action, pid, app_id, chkpt_sn);

	unset_ghost_fs(&oldfs);
	return task;
}

/**
 *  Main kernel entry function to restart a checkpointed task.
 *  @author Geoffroy Vallée
 *
 *  @param pid		Pid of the task to restart
 *  @param app_id	Application id
 *  @param chkpt_sn	Sequence number of the checkpoint
 *
 *  @return		New task if success, PTR_ERR if failure
 */
struct task_struct *restart_process(pid_t pid, long app_id, int chkpt_sn)
{
	struct epm_action action;
	struct task_struct *task;

	/* Check if the process has not been already restarted */
	if (find_task_by_kpid(pid) != NULL)
		return ERR_PTR(-EALREADY);

	action.type = EPM_CHECKPOINT;
	action.restart.shared = CR_LINK_ONLY;
	action.restart.app = find_local_app(app_id);

	BUG_ON(!action.restart.app);

	task = restart_task(&action, pid, app_id, chkpt_sn);
	if (IS_ERR(task))
		ckpt_err(&action, PTR_ERR(task),
			 "Fail to restart process %d",
			 pid);

	return task;
}
