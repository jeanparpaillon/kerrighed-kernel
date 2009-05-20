/**
 *  Process restart interface.
 *  @file restart.h
 *
 *  Definition of process restart interface.
 *  @author Geoffroy Vallée, Matthieu Fertré
 */

#ifndef __RESTART_H__
#define __RESTART_H__

#include <linux/types.h>

struct task_struct;

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/

struct task_struct *restart_process(pid_t pid, long app_id, int chkpt_sn);

#endif /* __RESTART_H__ */
