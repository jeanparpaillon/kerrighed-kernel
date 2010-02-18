/*
 *  kerrighed/epm/application_cr_api.c
 *
 *  Copyright (C) 1999-2006 INRIA, Universite de Rennes 1, EDF
 *  Copyright (C) 2007-2008 Matthieu Fertré - INRIA
 */

#include <kerrighed/pid.h>
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
int sys_app_freeze(struct checkpoint_info *infos)
{
	return app_freeze(infos);
}

/**
 *  System call function to unfreeze an application.
 *  @author Matthieu Fertré
 */
int sys_app_unfreeze(struct checkpoint_info *infos)
{
	return app_unfreeze(infos);
}

/**
 *  System call function to checkpoint an application.
 *  @author Matthieu Fertré
 */
int sys_app_chkpt(struct checkpoint_info *infos)
{
	return app_chkpt(infos);
}

/**
 *  System call function to restart an application
 *  @author Matthieu Fertré
 */
int sys_app_restart(struct restart_request *req)
{
	task_identity_t requester;

	requester.pid = task_pid_knr(current);
	requester.tgid = task_tgid_knr(current);

	return app_restart(req, &requester);
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
int sys_app_get_userdata(struct app_userdata_request *data_req)
{
	return app_get_userdata(data_req->app_id, data_req->flags,
				&data_req->user_data);
}

/**
 *  System call function to disable use of checkpoint for current application
 *  @author Matthieu Fertré
 */
int sys_app_cr_disable(void)
{
	return app_cr_disable();
}

/**
 *  System call function to enable again use of checkpoint for
 *  current application
 *  @author Matthieu Fertré
 */
int sys_app_cr_enable(void)
{
	return app_cr_enable();
}

int sys_app_cr_exclude(struct cr_mm_region *mm_regions)
{
	return app_cr_exclude(mm_regions);
}
