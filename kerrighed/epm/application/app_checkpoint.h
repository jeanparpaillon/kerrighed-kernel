/**
 *  Application checkpoint
 *  @author Matthieu Fertré
 */

#ifndef __APPLICATION_CHECKPOINT_H__
#define __APPLICATION_CHECKPOINT_H__

#include <kerrighed/sys/checkpoint.h>

int app_freeze(struct checkpoint_info *info);

int app_unfreeze(struct checkpoint_info *info);

int app_chkpt(struct checkpoint_info *info);

void application_checkpoint_rpc_init(void);

#endif /* __APPLICATION_CHECKPOINT_H__ */
