/*
 * net/tipc/tipc_node.h: Include file for TIPC node management routines
 * 
 * Copyright (c) 2000-2006, Ericsson AB
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

#ifndef _TIPC_NODE_H
#define _TIPC_NODE_H

#include "tipc_addr.h"
#include "tipc_bearer.h"
#include "tipc_net.h"

/**
 * struct tipc_node - TIPC node structure
 * @elm: generic network element structure for node
 * @node_list: adjacent entries in sorted list of nodes
 * @active_links: pointers to active links to node
 * @links: pointers to all links to node
 * @working_links: number of working links to node (both active and standby)
 * @link_cnt: number of links to node
 * @working_links: number of working links to node (both active and standby)
 * @permit_changeover: non-zero if node has redundant links to this system
 * @cleanup_required: non-zero if cleaning up after a prior loss of contact
 * @signature: random node instance identifier (always 0 for a uni-cluster node)
 * @flags: bit array indicating node's capabilities
 * @bclink: broadcast-related info
 *    @supported: non-zero if node supports TIPC b'cast capability
 *    @acked: sequence # of last outbound b'cast message acknowledged by node
 *    @last_in: sequence # of last in-sequence b'cast message received from node
 *    @last_sent: sequence # of last b'cast message sent by node
 *    @oos_state: state tracker for handling OOS b'cast messages
 *    @deferred_size: number of OOS b'cast messages in deferred queue
 *    @deferred_head: oldest OOS b'cast message received from node
 *    @deferred_tail: newest OOS b'cast message received from node
 *    @defragm: list of partially reassembled b'cast message fragments from node
 */
 
struct tipc_node {
	struct net_element elm;			/* MUST BE FIRST */
	struct list_head node_list;
	struct link *active_links[2];
	struct link *links[TIPC_MAX_BEARERS];
	int link_cnt;
	int working_links;
	int permit_changeover;
	int cleanup_required;
	u16 signature;
	u16 flags;
	struct {
		int supported;
		u32 acked;
		u32 last_in;
		u32 last_sent;
		u32 oos_state;
		u32 deferred_size;
		struct sk_buff *deferred_head;
		struct sk_buff *deferred_tail;
		struct sk_buff *defragm;
	} bclink;
};

struct tipc_node *tipc_node_create(u32 addr);
void tipc_node_delete(struct tipc_node *n_ptr);
void tipc_node_link_up(struct tipc_node *n_ptr, struct link *l_ptr);
void tipc_node_link_down(struct tipc_node *n_ptr, struct link *l_ptr);
int tipc_node_has_redundant_links(struct tipc_node *n_ptr);
int tipc_node_is_up(struct tipc_node *n_ptr);
struct tipc_node *tipc_node_attach_link(struct link *l_ptr);
void tipc_node_detach_link(struct tipc_node *n_ptr, struct link *l_ptr);
struct sk_buff *tipc_node_get_nodes(const void *req_tlv_area, int req_tlv_space);
struct sk_buff *tipc_node_get_links(const void *req_tlv_area, int req_tlv_space);


static inline void tipc_node_lock(struct tipc_node *n_ptr)
{
        net_element_lock(&n_ptr->elm);	
}

static inline void tipc_node_unlock(struct tipc_node *n_ptr)
{
        net_element_unlock(&n_ptr->elm);	
}


#endif
