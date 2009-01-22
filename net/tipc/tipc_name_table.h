/*
 * net/tipc/tipc_name_table.h: Include file for TIPC name table code
 *
 * Copyright (c) 2000-2006, Ericsson AB
 * Copyright (c) 2004-2007, Wind River Systems
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

#ifndef _TIPC_NAME_TABLE_H
#define _TIPC_NAME_TABLE_H

#include "tipc_net.h"
#include "tipc_bcast.h"
#include "tipc_topsrv.h"

/*
 * TIPC name types reserved for internal TIPC use (both current and planned)
 */

#define TIPC_ZM_SRV 3  		/* zone master service name type */


/**
 * struct publication - info about a published (name or) name sequence
 * @type: name sequence type
 * @lower: name sequence lower bound
 * @upper: name sequence upper bound
 * @scope: scope of publication
 * @node: network address of publishing port's node
 * @ref: publishing port
 * @key: publication key
 * @subscr: network element subscription (used to withdraw unreachable names)
 * @distr_list: adjacent entries in list of publications with same distribution needs
 * @pport_list: adjacent entries in list of publications made by this port
 * @node_list_next: next matching name seq publication with >= node scope
 * @cluster_list_next: next matching name seq publication with >= cluster scope
 * @zone_list_next: next matching name seq publication with >= zone scope
 * 
 * Note that the node list, cluster list, and zone list are circular lists.
 */

struct publication {
	u32 type;
	u32 lower;
	u32 upper;
	u32 scope;
	u32 node;
	u32 ref;
	u32 key;
	struct net_subscr subscr;
	struct list_head distr_list;
	struct list_head pport_list;
	struct publication *node_list_next;
	struct publication *cluster_list_next;
	struct publication *zone_list_next;
};


DECLARE_RWLOCK(tipc_nametbl_lock);
DECLARE_RWLOCK(tipc_routetbl_lock);

extern struct name_seq *route_table;
extern int tipc_own_routes;
extern int tipc_all_routes;


struct sk_buff *tipc_nametbl_get(const void *req_tlv_area, int req_tlv_space);
u32 tipc_nametbl_translate(u32 type, u32 instance, u32 *node);
int tipc_nametbl_mc_translate(u32 type, u32 lower, u32 upper, u32 limit,
			 struct port_list *dports);
int tipc_publish_rsv(u32 ref, unsigned int scope, 
                     struct tipc_name_seq const *seq);
struct publication *tipc_nametbl_publish(u32 type, u32 lower, u32 upper,
					 u32 scope, u32 port_ref, u32 key);

struct publication *tipc_nametbl_publish_rsv(u32 type, u32 lower, u32 upper,
					     u32 scope, u32 port_ref, u32 key);

void tipc_nametbl_withdraw(u32 type, u32 lower, u32 ref, u32 key);

struct publication *tipc_nametbl_insert_publ(u32 type, u32 lower, u32 upper,
					u32 scope, u32 node, u32 ref, u32 key);
struct publication *tipc_nameseq_insert_publ(struct name_seq *nseq,
					     u32 type, u32 lower, u32 upper,
					     u32 scope, u32 node, u32 port, u32 key);
struct publication *tipc_nametbl_remove_publ(u32 type, u32 lower, 
					u32 node, u32 ref, u32 key);
struct publication *tipc_nameseq_remove_publ(struct name_seq *nseq, u32 inst,
					     u32 node, u32 ref, u32 key);

void tipc_nametbl_subscribe(struct subscription *s);
void tipc_nametbl_unsubscribe(struct subscription *s);
int tipc_nametbl_init(void);
void tipc_nametbl_stop(void);

int tipc_routetbl_init(void);
void tipc_routetbl_stop(void);
u32 tipc_routetbl_translate(u32 target);
void tipc_routetbl_publish(unsigned long node_addr);
void tipc_routetbl_withdraw(unsigned long node_addr);
void tipc_routetbl_withdraw_node(unsigned long node_addr);
void tipc_routetbl_purge(u32 region_addr);
struct sk_buff *tipc_nametbl_get_routes(const void *req_tlv_area,
					int req_tlv_space);

#endif
