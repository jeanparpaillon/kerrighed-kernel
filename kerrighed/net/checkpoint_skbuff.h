
#ifndef __KRGIP_CHECKPOINT_SKBUFF_H__
#define __KRGIP_CHECKPOINT_SKBUFF_H__

#include <linux/net.h>
#include <linux/skbuff.h>

#include <kerrighed/action.h>
#include <kerrighed/ghost.h>

int krgip_import_buffers(struct epm_action *action, ghost_t *ghost, struct sk_buff_head *skblist);
int krgip_export_buffers(struct epm_action *action, ghost_t *ghost, struct sk_buff_head *skblist);

#endif
