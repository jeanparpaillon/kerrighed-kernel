/**
 *  Application checkpoint
 *  @author Matthieu Fertré
 */

#ifndef __APPLICATION_CHECKPOINT_H__
#define __APPLICATION_CHECKPOINT_H__

#include <kerrighed/sys/checkpoint.h>

int app_freeze(checkpoint_infos_t *infos);

int app_unfreeze(checkpoint_infos_t *infos);

int app_chkpt(checkpoint_infos_t *infos);

void application_checkpoint_rpc_init(void);

#endif /* __APPLICATION_CHECKPOINT_H__ */
