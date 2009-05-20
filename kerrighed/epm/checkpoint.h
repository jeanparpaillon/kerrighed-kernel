/**
 *  Process checkpoint interface.
 *  @file checkpoint.h
 *
 *  Definition of process checkpointing interface.
 *  @author Geoffroy Vallée, Renaud Lottiaux
 */

#ifndef __CHECKPOINT_H__
#define __CHECKPOINT_H__

#include <linux/types.h>

struct task_struct;

typedef enum {
	CHKPT_NO_OPTION,
	CHKPT_ONLY_STOP
} chkpt_option_t;

#define si_option(info)  (*(chkpt_option_t *) &(info)._sifields._pad)

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/

int can_be_checkpointed(struct task_struct *task_to_checkpoint);

#endif /* __CHECKPOINT_H__ */
