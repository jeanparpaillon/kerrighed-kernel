/*
 *  kerrighed/epm/application_cr_api.c
 *
 *  Copyright (C) 1999-2006 INRIA, Universite de Rennes 1, EDF
 *  Copyright (C) 2007-2008 Matthieu Fertré - INRIA
 */

#include <kerrighed/sys/checkpoint.h>
#include <kerrighed/application.h>
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
int sys_app_freeze(checkpoint_infos_t *infos)
{
	return app_freeze(infos);
}

/**
 *  System call function to unfreeze an application.
 *  @author Matthieu Fertré
 */
int sys_app_unfreeze(checkpoint_infos_t *infos)
{
	return app_unfreeze(infos);
}

/**
 *  System call function to checkpoint an application.
 *  @author Matthieu Fertré
 */
int sys_app_chkpt(checkpoint_infos_t *infos)
{
	return app_chkpt(infos);
}

/**
 *  System call function to restart an application
 *  @author Matthieu Fertré
 */
int sys_app_restart(restart_request_t *req, pid_t *root_pid)
{
	task_identity_t requester;

	requester.pid = current->pid;
	requester.tgid = current->tgid;

	return app_restart(req, &requester, root_pid);
}

/**
 *  System call function to set a user data per application
 *  @author Matthieu Fertré
 */
int sys_app_set_userdata(__u64 data)
{
	return app_set_userdata(data);
}

/**
 *  System call function to get a user data per application
 *  @author Matthieu Fertré
 */
int sys_app_get_userdata(app_userdata_request_t *data_req)
{
	return app_get_userdata(data_req->app_id, data_req->type,
				&data_req->user_data);
}
