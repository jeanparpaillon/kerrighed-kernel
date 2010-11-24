/*
 *  kerrighed/epm/network_ghost.c
 *
 *  Copyright (C) 1999-2006 INRIA, Universite de Rennes 1, EDF
 *  Copyright (C) 2006-2007 Pascal Gallard - Kerlabs, Louis Rilling - Kerlabs
 */

#include <linux/sched.h>
#include <kerrighed/pid.h>
#include <kerrighed/action.h>
#include <kerrighed/ghost.h>
#include <net/krgrpc/rpc.h>
#include "ghost.h"

pid_t send_task(struct rpc_desc *desc,
		struct task_struct *tsk,
		struct pt_regs *task_regs,
		struct epm_action *action)
{
	pid_t pid_remote_task = -1;
	ghost_t *ghost;
	int err;

	ghost = create_network_ghost(GHOST_WRITE | GHOST_READ, desc);
	if (IS_ERR(ghost)) {
		err = PTR_ERR(ghost);
		goto out;
	}

	err = rpc_pack_type(desc, *action);
	if (err)
		goto out_close;

	err = export_process(action, ghost, tsk, task_regs);
	if (err)
		goto out_close;

	err = rpc_unpack_type(desc, pid_remote_task);
	post_export_process(action, ghost, tsk);

out_close:
	ghost_close(ghost);

out:
	return err ? err : pid_remote_task;
}

struct task_struct *recv_task(struct rpc_desc *desc, struct epm_action *action)
{
	struct task_struct *new_tsk;
	ghost_t *ghost;
	pid_t pid;
	int err;

	ghost = create_network_ghost(GHOST_READ | GHOST_WRITE, desc);
	if (IS_ERR(ghost))
		goto err_ghost;

	new_tsk = import_process(action, ghost);
	if (IS_ERR(new_tsk))
		goto err_close;

	krg_action_stop(new_tsk, action->type);

	pid = task_pid_knr(new_tsk);
	err = rpc_pack_type(desc, pid);
	if (err)
		goto err_close;

	ghost_close(ghost);

	return new_tsk;

err_close:
	ghost_close(ghost);
err_ghost:
	/* TODO: send a custom error code */
	return NULL;
}
