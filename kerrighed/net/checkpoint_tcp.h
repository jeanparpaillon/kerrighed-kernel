/*
 *  kerrighed/net/checkpoint_tcp.h
 *
 *  Copyright (C) 2010, Emmanuel Thierry - Kerlabs
 */

#ifndef __KRGIP_CHECKPOINT_TCP_H__
#define __KRGIP_CHECKPOINT_TCP_H__

#include <linux/net.h>

#include <kerrighed/action.h>
#include <kerrighed/ghost.h>

int krgip_import_tcp(struct epm_action *action, ghost_t *ghost, struct socket *sock);
int krgip_export_tcp(struct epm_action *action, ghost_t *ghost, struct socket *sock);

#endif
