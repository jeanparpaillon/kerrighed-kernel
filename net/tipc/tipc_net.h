/*
 * net/tipc/tipc_net.h: Include file for TIPC network routing code
 * 
 * Copyright (c) 1995-2006, Ericsson AB
 * Copyright (c) 2005-2008, Wind River Systems
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the names of the copyright holders nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") version 2 as published by the Free
 * Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _TIPC_NET_H
#define _TIPC_NET_H

#include "tipc_addr.h"

#define LOWEST_SLAVE  2048u
#define TIPC_ROUTE 2

/**
 * struct net_element - generic network element (for node, cluster, or zone)
 * @addr: address of element (i.e. <Z.C.N>, <Z.C.0>, or <Z.0.0>)
 * @nsub: list of subscribers to notify when element is unavailable
 * @lock: lock for exclusive access to element
 */

struct net_element {
        u32 addr;
        struct list_head nsub;
	spinlock_t lock;
};

typedef void (*net_ev_handler) (void *usr_handle);

/**
 * struct net_subscr - network element subscription entry
 * @addr: network address of entity being monitored
 * @element: network element containing entity being monitored (NULL, if none)
 * @sub_list: adjacent entries in list of network element subscriptions
 * @handle_element_down: routine to invoke when monitored entity is unreachable
 * @usr_handle: argument to pass to routine
 */

struct net_subscr {
	u32 addr;
	struct net_element *element;
	struct list_head sub_list;
	net_ev_handler handle_element_down;
	void *usr_handle;
};

typedef struct {
	struct net_element **element;
	int max_size;
	int first_free;
} net_element_set_t;

extern net_element_set_t tipc_local_nodes;
extern net_element_set_t tipc_remote_nodes;
extern net_element_set_t tipc_regions;

DECLARE_RWLOCK(tipc_net_lock);

struct tipc_node;

int tipc_net_start(u32 addr);
void tipc_net_stop(void);
void tipc_net_route_msg(struct sk_buff *buf);
struct tipc_node *tipc_net_find_node(u32 addr);
struct tipc_node *tipc_net_select_node(u32 addr);
struct net_element *tipc_net_lookup_element(u32 addr, net_element_set_t *set); 
void tipc_net_attach_node(struct tipc_node *n_ptr);

void tipc_netsub_bind(struct net_subscr *net_sub, u32 addr,
		      net_ev_handler handle_down, void *usr_handle);
void tipc_netsub_unbind(struct net_subscr *net_sub);

void tipc_netsub_notify(struct net_element *element, u32 affected_addr);


static inline void net_element_lock(struct net_element *e_ptr)
{
	spin_lock_bh(&e_ptr->lock);
}

static inline void net_element_unlock(struct net_element *e_ptr)
{
	spin_unlock_bh(&e_ptr->lock);
}


#endif
