/**
 *  Application checkpoint and restart API interface.
 *  @file application_cr_api.h
 *
 *  Definition of global coordinated process checkpointing and restarting
 *  interface.
 *
 *  @author Matthieu Fertré
 */

#ifndef __APPLICATION_CR_API_H__
#define __APPLICATION_CR_API_H__

#include <kerrighed/sys/checkpoint.h>

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/

/**
 *  System call function to checkpoint an application
 *  @author Matthieu Fertré
 */
int sys_app_freeze(checkpoint_infos_t *infos);

/**
 *  System call function to checkpoint an application
 *  @author Matthieu Fertré
 */
int sys_app_unfreeze(checkpoint_infos_t *infos);

/**
 *  System call function to checkpoint an application
 *  @author Matthieu Fertré
 */
int sys_app_chkpt(checkpoint_infos_t *infos);

/**
 *  System call function to restart an application.
 *  @author Matthieu Fertré
 */
int sys_app_restart(restart_request_t *req, pid_t *root_pid);

/**
 *  System call function to set a user data per application
 *  @author Matthieu Fertré
 */
int sys_app_set_userdata(__u64 data);

/**
 *  System call function to get a user data per application
 *  @author Matthieu Fertré
 */
int sys_app_get_userdata(app_userdata_request_t *data_req);

#endif /* __APPLICATION_CR_API_H__ */
