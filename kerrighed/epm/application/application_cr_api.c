/*
 *  kerrighed/epm/application_cr_api.c
 *
 *  Copyright (C) 1999-2006 INRIA, Universite de Rennes 1, EDF
 *  Copyright (C) 2007-2008 Matthieu Fertré - INRIA
 */

#include <kerrighed/pid.h>
#include <kerrighed/sys/checkpoint.h>
#include <kerrighed/application.h>

#define MODULE_NAME "Application C/R API"

#include "../debug_epm.h"

#include "application_cr_api.h"
#include "app_checkpoint.h"
#include "app_restart.h"

/*****************************************************************************/
/*                                                                           */
/*                                SYS CALL FUNCTIONS                         */
/*                                                                           */
/*****************************************************************************/

/**
 *  System call function to freeze an application.
 *  @author Matthieu Fertré
 */
int sys_app_freeze(struct checkpoint_info *infos)
{
	int r;

	DEBUG(DBG_CKPT_API, 1, "Freezing application %ld\n", infos->app_id);

	r = app_freeze(infos);

	return r;
}

/**
 *  System call function to unfreeze an application.
 *  @author Matthieu Fertré
 */
int sys_app_unfreeze(struct checkpoint_info *infos)
{
	int r;

	DEBUG(DBG_CKPT_API, 1, "Unfreezing application %ld\n", infos->app_id);

	r = app_unfreeze(infos);

	return r;
}

/**
 *  System call function to checkpoint an application.
 *  @author Matthieu Fertré
 */
int sys_app_chkpt(struct checkpoint_info *infos)
{
	int r;

	DEBUG(DBG_CKPT_API, 1, "Checkpoint application %ld\n", infos->app_id);

	r = app_chkpt(infos);

	DEBUG(DBG_CKPT_API, 1,
	      "Checkpoint application %ld : done with err %d\n", infos->app_id,
	      r);

	return r;
}

/**
 *  System call function to restart an application
 *  @author Matthieu Fertré
 */
int sys_app_restart(struct restart_request *req, pid_t *root_pid)
{
	int r;
	task_identity_t requester;

	DEBUG(DBG_CKPT_API, 1, "Restart application with %ld-%d \n",
	      req->app_id, req->chkpt_sn);

	requester.pid = task_pid_knr(current);
	requester.tgid = task_tgid_knr(current);

	r = app_restart(req, &requester, root_pid);

	DEBUG(DBG_CKPT_API, 1,
	      "Restart application %ld-%d : done with err %d\n", req->app_id,
	      req->chkpt_sn, r);

	return r;
}

/**
 *  System call function to set a user data per application
 *  @author Matthieu Fertré
 */
int sys_app_set_userdata(__u64 data)
{
	int r;

	r = app_set_userdata(data);

	return r;
}

/**
 *  System call function to get a user data per application
 *  @author Matthieu Fertré
 */
int sys_app_get_userdata(struct app_userdata_request *data_req)
{
	return app_get_userdata(data_req->app_id, data_req->flags,
				&data_req->user_data);
}
