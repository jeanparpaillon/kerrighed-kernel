

#ifndef __KRGIP_CHECKPOINT_SOCK_H__
#define __KRGIP_CHECKPOINT_SOCK_H__

#include <linux/net.h>

#include <kerrighed/action.h>
#include <kerrighed/ghost.h>

int krgip_export_sock(struct epm_action *action, ghost_t *ghost, struct socket *sock);
int krgip_import_sock(struct epm_action *action, ghost_t *ghost, struct socket *sock);

#endif
