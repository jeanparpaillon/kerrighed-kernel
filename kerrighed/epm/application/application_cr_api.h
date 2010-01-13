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
int sys_app_freeze(struct checkpoint_info *info);

/**
 *  System call function to checkpoint an application
 *  @author Matthieu Fertré
 */
int sys_app_unfreeze(struct checkpoint_info *info);

/**
 *  System call function to checkpoint an application
 *  @author Matthieu Fertré
 */
int sys_app_chkpt(struct checkpoint_info *info);

/**
 *  System call function to restart an application
 *  @author Matthieu Fertré
 */
int sys_app_restart(struct restart_request *req);

/**
 *  System call function to set a user data per application
 *  @author Matthieu Fertré
 */
int sys_app_set_userdata(__u64 data);

/**
 *  System call function to get a user data per application
 *  @author Matthieu Fertré
 */
int sys_app_get_userdata(struct app_userdata_request *data_req);

/**
 *  System call function to disable use of checkpoint for current application
 *  @author Matthieu Fertré
 */
int sys_app_cr_disable(void);

/**
 *  System call function to enable again use of checkpoint for
 *  current application
 *  @author Matthieu Fertré
 */
int sys_app_cr_enable(void);


int sys_app_cr_exclude(struct cr_mm_region *mm_regions);

#endif /* __APPLICATION_CR_API_H__ */
