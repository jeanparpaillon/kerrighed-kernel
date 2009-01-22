/*
 * net/tipc/tipc_net.c: TIPC network routing code
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

#include "tipc_core.h"
#include "tipc_bearer.h"
#include "tipc_net.h"
#include "tipc_addr.h"
#include "tipc_name_table.h"
#include "tipc_name_distr.h"
#include "tipc_topsrv.h"
#include "tipc_link.h"
#include "tipc_msg.h"
#include "tipc_port.h"
#include "tipc_bcast.h"
#include "tipc_discover.h"
#include "tipc_cfgsrv.h"

/*
 * The TIPC locking policy is designed to ensure a very fine locking
 * granularity, permitting complete parallel access to individual
 * port and node/link instances. The code consists of three major
 * locking domains, each protected with their own disjunct set of locks.
 *
 * 1: The routing hierarchy.
 *    Comprises the structures 'net', 'node', 'link' 
 *    and 'bearer'. The whole hierarchy is protected by a big
 *    read/write lock, tipc_net_lock, to enssure that nothing is added
 *    or removed while code is accessing any of these structures.
 *    This layer must not be called from the two others while they
 *    hold any of their own locks.
 *    Neither must it itself do any upcalls to the other two before
 *    it has released tipc_net_lock and other protective locks.
 *
 *   Within the tipc_net_lock domain there are two sub-domains;'node' and
 *   'bearer', where local write operations are permitted,
 *   provided that those are protected by individual spin_locks
 *   per instance. Code holding tipc_net_lock(read) and a node spin_lock
 *   is permitted to poke around in both the node itself and its
 *   subordinate links. I.e, it can update link counters and queues,
 *   change link state, send protocol messages, and alter the
 *   "active_links" array in the node; but it can _not_ remove a link
 *   or a node from the overall structure.
 *   Correspondingly, individual bearers may change status within a
 *   tipc_net_lock(read), protected by an individual spin_lock ber bearer
 *   instance, but it needs tipc_net_lock(write) to remove/add any bearers.
 *
 *
 *  2: The transport level of the protocol.
 *     This consists of the structures port, (and its user level
 *     representations, such as user_port and tipc_sock), reference and
 *     tipc_user (port.c, reg.c, socket.c).
 *
 *     This layer has four different locks:
 *     - The tipc_port spin_lock. This is protecting each port instance
 *       from parallel data access and removal. Since we can not place
 *       this lock in the port itself, it has been placed in the
 *       corresponding reference table entry, which has the same life
 *       cycle as the module. This entry is difficult to access from
 *       outside the TIPC core, however, so a pointer to the lock has
 *       been added in the port instance, -to be used for unlocking
 *       only.
 *     - A read/write lock to protect the reference table itself (ref.c). 
 *       (Nobody is using read-only access to this, so it can just as
 *       well be changed to a spin_lock)
 *     - A spin lock to protect the registry of kernel/driver users (reg.c)
 *     - A global spin_lock (tipc_port_lock), which only task is to ensure
 *       consistency where more than one port is involved in an operation,
 *       i.e., whe a port is part of a linked list of ports.
 *       There are two such lists; 'port_list', which is used for management,
 *       and 'wait_list', which is used to queue ports during congestion.
 *
 *  3: The name table
 *     - One master read/write lock (tipc_nametbl_lock) protects the overall
 *       name table structure.  Nothing must be added/removed to this structure
 *       without holding write access to it.
 *     - An additional "subsequence update" spin_lock exists per sequence; it
 *	 is used when the head pointer of one of a subsequence's circular lists
 *	 of publications is advanced during name table lookup operations.
 *	 (It could have been implemented as a "per subsequence" lock, but was
 *	 made "per sequence" to reduce the footprint of the name table entries.)
 *	 The subsequence update lock can only be used within the scope of
 *	 a tipc_nametbl_lock(read).
 */

DEFINE_RWLOCK(tipc_net_lock);

net_element_set_t tipc_local_nodes = { NULL, 0, 0 };
net_element_set_t tipc_remote_nodes = { NULL, 0, 0 };
net_element_set_t tipc_regions = { NULL, 0, 0 };


static void net_element_set_init(net_element_set_t *set, int num_elements)
{
	void *ptr = kcalloc(num_elements, sizeof(struct net_element *),
			     GFP_ATOMIC);

	if (ptr != NULL) {
		set->element = ptr;
		set->max_size = num_elements;
		set->first_free = 0;
	}
}

static void net_element_set_term(net_element_set_t *set)
{
	kfree(set->element);
	memset(set, 0, sizeof(net_element_set_t));
}

struct net_element *tipc_net_lookup_element(u32 addr, net_element_set_t *set) 
{
	int low = 0;
	int high = set->first_free - 1;
	int mid;

	while (low <= high) {
		mid = (low + high) / 2;
		if (addr < set->element[mid]->addr)
			high = mid - 1;
		else if (addr > set->element[mid]->addr)
			low = mid + 1;
		else
			return set->element[mid];
	}
	return NULL;
}

static void net_insert_element(struct net_element *e_ptr, net_element_set_t *set) 
{
	int i;

	if (set->first_free >= set->max_size) {
		warn("Could not add element %x (max %u allowed for this type)\n",
		     e_ptr->addr, set->max_size);
		return;
	}

	for (i = 0; i < set->first_free; i++) {
		dbg_assert(set->element[i]->addr != e_ptr->addr);
		if (set->element[i]->addr > e_ptr->addr) {
			int sz = (set->first_free - i) * sizeof(e_ptr);
			memmove(&set->element[i+1], &set->element[i], sz);
			break;
		}
	}
	set->element[i] = e_ptr;
	set->first_free++;
}

/**
 * tipc_net_attach_node - record new neighbor node
 */

void tipc_net_attach_node(struct tipc_node *n_ptr)
{
	if (in_own_cluster(n_ptr->elm.addr)) {
		net_insert_element(&n_ptr->elm, &tipc_local_nodes);
	} else {
		net_insert_element(&n_ptr->elm, &tipc_remote_nodes);
	}
}


/**
 * tipc_net_find_node - get specified neighbor node
 * @addr: network address of node
 * 
 * Returns pointer to node (or NULL if node is not a known neighbor)
 * 
 * CAUTION: Just because a node is a known neighbor, it does not mean
 *          there are currently working links to it!
 */

struct tipc_node *tipc_net_find_node(u32 addr)
{
	if (in_own_cluster(addr))
		return (struct tipc_node *)tipc_net_lookup_element(
			addr, &tipc_local_nodes);
	else
		return (struct tipc_node *)tipc_net_lookup_element(
			addr, &tipc_remote_nodes);
}

/**
 * tipc_net_select_node - select next hop node to use for off-node message
 * @addr: network address of message destination (may be node, cluster, or zone)
 * 
 * Returns pointer to node to use (or NULL if destination is unreachable)
 */

struct tipc_node *tipc_net_select_node(u32 addr)
{
	dbg_assert(addr != tipc_own_addr);
	dbg_assert(addr != addr_cluster(tipc_own_addr));
	dbg_assert(addr != addr_zone(tipc_own_addr));
	dbg_assert(addr != 0);

	if (likely(in_own_cluster(addr)))
		return (struct tipc_node *)tipc_net_lookup_element(addr,
							      &tipc_local_nodes);
	else
		return tipc_net_find_node(tipc_routetbl_translate(addr));
}


static void net_route_named_msg(struct sk_buff *buf)
{
	struct tipc_msg *msg = buf_msg(buf);
	u32 dnode;
	u32 dport;

	if (!msg_named(msg)) {
		msg_dbg(msg, "tipc_net->drop_nam:");
		buf_discard(buf);
		return;
	}

	dnode = addr_domain(msg_lookup_scope(msg));
	dport = tipc_nametbl_translate(msg_nametype(msg), msg_nameinst(msg),
				       &dnode);

	if (dport) {
		msg_set_destnode(msg, dnode);
		msg_set_destport(msg, dport);
		tipc_net_route_msg(buf);
		return;
	}
	msg_dbg(msg, "tipc_net->rej:NO NAME: ");
	tipc_reject_msg(buf, TIPC_ERR_NO_NAME);
}

void tipc_net_route_msg(struct sk_buff *buf)
{
	struct tipc_msg *msg;
	u32 dnode;

	if (!buf)
		return;
	msg = buf_msg(buf);

	msg_incr_reroute_cnt(msg);
	if (msg_reroute_cnt(msg) > 6) {
		if (msg_errcode(msg)) {
			msg_dbg(msg, "NET>DISC>:");
			buf_discard(buf);
		} else {
			msg_dbg(msg, "NET>REJ>:");
			tipc_reject_msg(buf, msg_destport(msg) ?
					TIPC_ERR_NO_PORT : TIPC_ERR_NO_NAME);
		}
		return;
	}

	msg_dbg(msg, "tipc_net->rout: ");

	/* Handle message for this node */

	dnode = msg_short(msg) ? msg_destnode_cache(msg) : msg_destnode(msg);
	if (tipc_in_scope(dnode, tipc_own_addr)) {
		if (msg_isdata(msg)) {
			if (msg_mcast(msg))
				tipc_port_recv_mcast(buf, NULL);
			else if (msg_destport(msg))
				tipc_port_recv_msg(buf);
			else
				net_route_named_msg(buf);
			return;
		}
		switch (msg_user(msg)) {
		case NAME_DISTRIBUTOR:
			tipc_named_recv(buf);
			break;
		case ROUTE_DISTRIBUTOR:
			tipc_route_recv(buf);
			break;
		case CONN_MANAGER:
			tipc_port_recv_proto_msg(buf);
			break;
		default:
			msg_dbg(msg,"DROP/NET/<REC<");
			buf_discard(buf);
		}
		return;
	}

	/* Handle message for another node */

	msg_dbg(msg, "NET>SEND>: ");
	pskb_trim(buf, msg_size(msg));
	tipc_link_send(buf, dnode, msg_link_selector(msg));
}

static int net_init(void)
{
	net_element_set_init(&tipc_local_nodes, tipc_max_nodes);
	net_element_set_init(&tipc_remote_nodes, tipc_max_remotes);
	net_element_set_init(&tipc_regions,
			     (tipc_max_clusters - 1) + (tipc_max_zones - 1));

	if ((tipc_local_nodes.element == NULL) ||
	    (tipc_remote_nodes.element == NULL) ||
	    (tipc_regions.element == NULL))
		return -ENOMEM;

	return 0;
}

static void net_stop(void)
{
	int i;

	for (i = 0; i < tipc_local_nodes.first_free; i++) {
		tipc_node_delete(
			(struct tipc_node *)tipc_local_nodes.element[i]);
	}

	for (i = 0; i < tipc_remote_nodes.first_free; i++) {
		tipc_node_delete(
			(struct tipc_node *)tipc_remote_nodes.element[i]);
	}

	for (i = 0; i < tipc_regions.first_free; i++) {
		spin_lock_term(&tipc_regions.element[i]->lock);
		kfree(tipc_regions.element[i]);
	}
	
	net_element_set_term(&tipc_local_nodes);
	net_element_set_term(&tipc_remote_nodes);
	net_element_set_term(&tipc_regions);
}


int tipc_net_start(u32 addr)
{
	char addr_string[16];
	int res;

	if (tipc_mode != TIPC_NODE_MODE)
		return -ENOPROTOOPT;

	tipc_cfg_stop();

	tipc_own_addr = addr;
	tipc_mode = TIPC_NET_MODE;
	tipc_port_reinit();
	tipc_named_reinit();

	if ((res = tipc_bearer_init()) ||
	    (res = net_init()) ||
	    (res = tipc_bclink_init())) {
		return res;
	}

	tipc_k_signal((Handler)tipc_cfg_init, 0);

	info("Started in network mode\n");
	tipc_addr_string_fill(addr_string, tipc_own_addr);
	info("Own node address %s, network identity %u\n",
	     addr_string, tipc_net_id);
	return 0;
}

void tipc_net_stop(void)
{
	if (tipc_mode != TIPC_NET_MODE)
		return;

	write_lock_bh(&tipc_net_lock);
	tipc_mode = TIPC_NODE_MODE;
	tipc_bearer_stop();
	tipc_bclink_stop();
	net_stop();
	write_unlock_bh(&tipc_net_lock);
	info("Left network mode \n");
}

/**
 * tipc_netsub_bind - create "element down" subscription
 */

void tipc_netsub_bind(struct net_subscr *net_sub, u32 addr, 
		      net_ev_handler handle_down, void *usr_handle)
{
	u32 elm_addr;

	net_sub->element = NULL;

	if (in_own_cluster(addr)) {
		elm_addr = addr;
		net_sub->element = tipc_net_lookup_element(elm_addr,
							   &tipc_local_nodes);
		dbg_assert(net_sub->element);
	} else {
		if (!in_own_zone(addr))
			elm_addr = addr_zone(addr);
		else
			elm_addr = addr_cluster(addr);

		net_sub->element = tipc_net_lookup_element(elm_addr,
							   &tipc_regions);
		if (net_sub->element == NULL) {
			struct net_element *region;

			region = kmalloc(sizeof(struct net_element), GFP_ATOMIC);
			if (region == NULL) {
				warn("Memory squeeze; unable to record new region\n");
				return;
			}
			region->addr = elm_addr;
			INIT_LIST_HEAD(&region->nsub);
			spin_lock_init(&region->lock);
			net_insert_element(region, &tipc_regions);
			net_sub->element = region;
		}
	}

	net_sub->addr = addr;
	net_sub->handle_element_down = handle_down;
	net_sub->usr_handle = usr_handle;

	net_element_lock(net_sub->element);
	list_add_tail(&net_sub->sub_list, &net_sub->element->nsub);
	net_element_unlock(net_sub->element);
}

/**
 * netsub_unsubscribe - cancel "element down" subscription (if any)
 */

void tipc_netsub_unbind(struct net_subscr *net_sub)
{
	if (!net_sub->element)
		return;

	net_element_lock(net_sub->element);
	list_del_init(&net_sub->sub_list);
	net_element_unlock(net_sub->element);
}

/** 
 * netsub_notify - notify subscribers that a network element is unreachable
 * @e_ptr: network element (either a node or a region)
 * @affected_addr: address of affected portion of network element
 *                 (may not be all of it)
 *                 
 * Note: network element is locked by caller
 */

void tipc_netsub_notify(struct net_element *e_ptr, u32 affected_addr)
{
	struct net_subscr *ns;
	struct net_subscr *tns;

	list_for_each_entry_safe(ns, tns, &e_ptr->nsub, sub_list) {
		if (tipc_in_scope(affected_addr, ns->addr)) {
			ns->element = NULL;
			list_del_init(&ns->sub_list);
			tipc_k_signal((Handler)ns->handle_element_down,
				      (unsigned long)ns->usr_handle);
		}
	}
}

