/*
 * net/tipc/tipc_node.c: TIPC node management routines
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

#include "tipc_core.h"
#include "tipc_cfgsrv.h"
#include "tipc_node.h"
#include "tipc_net.h"
#include "tipc_addr.h"
#include "tipc_node.h"
#include "tipc_link.h"
#include "tipc_port.h"
#include "tipc_bearer.h"
#include "tipc_name_distr.h"

static void node_lost_contact(struct tipc_node *n_ptr);
static void node_established_contact(struct tipc_node *n_ptr);

static LIST_HEAD(nodes_list);	/* sorted list of neighboring nodes */
static int node_count = 0;     	/* number of neighboring nodes that exist */
static int link_count = 0;     	/* number of unicast links node currently has */

static DEFINE_SPINLOCK(node_create_lock);

/**
 * tipc_node_create - create neighboring node
 *
 * Currently, this routine is called by neighbor discovery code, which holds
 * net_lock for reading only.  We must take node_create_lock to ensure a node
 * isn't created twice if two different bearers discover the node at the same
 * time.  (It would be preferable to switch to holding net_lock in write mode,
 * but this is a non-trivial change.)
 */

struct tipc_node *tipc_node_create(u32 addr)
{
	struct tipc_node *n_ptr;
	struct tipc_node *curr_n_ptr;

	spin_lock_bh(&node_create_lock);

	n_ptr = tipc_net_find_node(addr);
	if (n_ptr != NULL) {
		spin_unlock_bh(&node_create_lock);
		return n_ptr;
	}

	n_ptr = kzalloc(sizeof(*n_ptr), GFP_ATOMIC);
	if (n_ptr != NULL) {
		n_ptr->elm.addr = addr;
		spin_lock_init(&n_ptr->elm.lock);
		INIT_LIST_HEAD(&n_ptr->elm.nsub);
		tipc_net_attach_node(n_ptr);

		list_for_each_entry(curr_n_ptr, &nodes_list, node_list) {
			if (addr < curr_n_ptr->elm.addr)
				break;
		}
		list_add_tail(&n_ptr->node_list, &curr_n_ptr->node_list);

		node_count++;
	} else {
		warn("Node creation failed, no memory\n");
	}

	spin_unlock_bh(&node_create_lock);
	return n_ptr;
}

void tipc_node_delete(struct tipc_node *n_ptr)
{
	node_count--;
	list_del(&n_ptr->node_list);
	spin_lock_term(&n_ptr->elm.lock);
	kfree(n_ptr);
}


/**
 * tipc_node_link_up - handle addition of link
 *
 * Link becomes active (alone or shared) or standby, depending on its priority.
 */

void tipc_node_link_up(struct tipc_node *n_ptr, struct link *l_ptr)
{
	struct link **active = &n_ptr->active_links[0];

	n_ptr->working_links++;

	info("Established link <%s> on network plane %c\n",
	     l_ptr->name, l_ptr->b_ptr->net_plane);

#ifdef CONFIG_TIPC_MULTIPLE_LINKS
	if (active[0] == NULL) {
		active[0] = active[1] = l_ptr;
		node_established_contact(n_ptr);
		return;
	}
	if (l_ptr->priority < active[0]->priority) {
		info("New link <%s> becomes standby\n", l_ptr->name);
		return;
	}
	tipc_link_send_duplicate(active[0], l_ptr);
	if (l_ptr->priority == active[0]->priority) {
		active[0] = l_ptr;
		return;
	}
	info("Old link <%s> becomes standby\n", active[0]->name);
	if (active[1] != active[0])
		info("Old link <%s> becomes standby\n", active[1]->name);
	active[0] = active[1] = l_ptr;
#else
	active[0] = active[1] = l_ptr;
	node_established_contact(n_ptr);
#endif
}

#ifdef CONFIG_TIPC_MULTIPLE_LINKS
/**
 * node_select_active_links - select active link
 */

static void node_select_active_links(struct tipc_node *n_ptr)
{
	struct link **active = &n_ptr->active_links[0];
	u32 i;
	u32 highest_prio = 0;

	active[0] = active[1] = NULL;

	for (i = 0; i < TIPC_MAX_BEARERS; i++) {
		struct link *l_ptr = n_ptr->links[i];

		if (!l_ptr || !tipc_link_is_up(l_ptr) ||
		    (l_ptr->priority < highest_prio))
			continue;

		if (l_ptr->priority > highest_prio) {
			highest_prio = l_ptr->priority;
			active[0] = active[1] = l_ptr;
		} else {
			active[1] = l_ptr;
		}
	}
}
#endif

/**
 * tipc_node_link_down - handle loss of link
 */

void tipc_node_link_down(struct tipc_node *n_ptr, struct link *l_ptr)
{
	struct link **active = &n_ptr->active_links[0];

	n_ptr->working_links--;

#ifdef CONFIG_TIPC_MULTIPLE_LINKS
	if (!tipc_link_is_active(l_ptr)) {
		info("Lost standby link <%s> on network plane %c\n",
		     l_ptr->name, l_ptr->b_ptr->net_plane);
		return;
	}

	info("Lost link <%s> on network plane %c\n",
	     l_ptr->name, l_ptr->b_ptr->net_plane);

	if (active[0] == l_ptr)
		active[0] = active[1];
	if (active[1] == l_ptr)
		active[1] = active[0];
	if (active[0] == l_ptr)
		node_select_active_links(n_ptr);
	if (tipc_node_is_up(n_ptr))
		tipc_link_changeover(l_ptr);
	else
		node_lost_contact(n_ptr);
#else
	info("Lost link <%s> on network plane %c\n",
	     l_ptr->name, l_ptr->b_ptr->net_plane);

	active[0] = active[1] = NULL;
	node_lost_contact(n_ptr);
#endif
}

int tipc_node_is_up(struct tipc_node *n_ptr)
{
	return (n_ptr->active_links[0] != NULL);
}

int tipc_node_has_redundant_links(struct tipc_node *n_ptr)
{
#ifdef CONFIG_TIPC_MULTIPLE_LINKS
	return (n_ptr->working_links > 1);
#else
	return 0;
#endif
}

struct tipc_node *tipc_node_attach_link(struct link *l_ptr)
{
	struct tipc_node *n_ptr = tipc_net_find_node(l_ptr->addr);

	if (!n_ptr)
		n_ptr = tipc_node_create(l_ptr->addr);
	if (n_ptr) {
		u32 bearer_id = l_ptr->b_ptr->identity;
		char addr_string[16];

		if (n_ptr->link_cnt >= TIPC_MAX_BEARERS) {
			tipc_addr_string_fill(addr_string, n_ptr->elm.addr);
			err("Attempt to more than %d links to %s\n",
			    n_ptr->link_cnt, addr_string);
			return NULL;
		}

		if (!n_ptr->links[bearer_id]) {
			n_ptr->links[bearer_id] = l_ptr;
			n_ptr->link_cnt++;
			link_count++;
			return n_ptr;
		}
		tipc_addr_string_fill(addr_string, l_ptr->addr);
		err("Attempt to establish second link on <%s> to %s \n",
		    l_ptr->b_ptr->publ.name, addr_string);
	}
	return NULL;
}

void tipc_node_detach_link(struct tipc_node *n_ptr, struct link *l_ptr)
{
	n_ptr->links[l_ptr->b_ptr->identity] = NULL;
	n_ptr->link_cnt--;
	link_count--;
}

static void node_established_contact(struct tipc_node *n_ptr)
{
	dbg("node_established_contact:-> %x\n", n_ptr->elm.addr);

	/* Synchronize broadcast acks */

	n_ptr->bclink.acked = tipc_bclink_get_last_sent();

	if (in_own_cluster(n_ptr->elm.addr)) {

		/* Add to multicast destination map, if applicable */

		if (n_ptr->bclink.supported)
			tipc_bclink_add_node(n_ptr->elm.addr);
	} else {

		/* Publish new inter-cluster (or inter-zone) route */

		tipc_k_signal((Handler)tipc_routetbl_publish, n_ptr->elm.addr);
	}

	/* Pass route & name table info to node, if necessary */

	if (in_own_zone(n_ptr->elm.addr)) {
		if (likely(n_ptr->flags & NF_MULTICLUSTER)) {
			tipc_k_signal((Handler)tipc_route_node_up,
				      n_ptr->elm.addr);
			tipc_k_signal((Handler)tipc_named_node_up,
				      n_ptr->elm.addr);
		} else {
			tipc_k_signal((Handler)tipc_named_node_up_uni,
				      n_ptr->elm.addr);
		}
	}
}

#ifdef CONFIG_TIPC_MULTIPLE_LINKS
static inline void node_abort_link_changeover(struct tipc_node *n_ptr)
{
	struct link *l_ptr;
	int i;

	for (i = 0; i < TIPC_MAX_BEARERS; i++) {
		l_ptr = n_ptr->links[i];
		if (l_ptr != NULL) {
			l_ptr->reset_checkpoint = l_ptr->next_in_no;
			l_ptr->exp_msg_count = 0;
			tipc_link_reset_fragments(l_ptr);
		}
	}
}
#endif

static void node_cleanup_finished(unsigned long node_addr)
{
	struct tipc_node *n_ptr;
	 
	read_lock_bh(&tipc_net_lock);
	n_ptr = tipc_net_find_node(node_addr);
	if (n_ptr) {
		tipc_node_lock(n_ptr);
		n_ptr->cleanup_required = 0;
		tipc_node_unlock(n_ptr);
	}
	read_unlock_bh(&tipc_net_lock);
}

static void node_lost_contact(struct tipc_node *n_ptr)
{
	char addr_string[16];

	tipc_addr_string_fill(addr_string, n_ptr->elm.addr);
	info("Lost contact with %s\n", addr_string);

	/* Clean up broadcast reception remains */

	while (n_ptr->bclink.deferred_head) {
		struct sk_buff *buf = n_ptr->bclink.deferred_head;

		n_ptr->bclink.deferred_head = buf->next;
		buf_discard(buf);
	}
	n_ptr->bclink.deferred_size = 0;

	if (n_ptr->bclink.defragm) {
		buf_discard(n_ptr->bclink.defragm);
		n_ptr->bclink.defragm = NULL;
	}

	if (in_own_cluster(n_ptr->elm.addr) && n_ptr->bclink.supported) { 
		tipc_bclink_acknowledge(n_ptr, mod(n_ptr->bclink.acked + 10000));
		tipc_bclink_remove_node(n_ptr->elm.addr);
	}

#ifdef CONFIG_TIPC_MULTIPLE_LINKS
	node_abort_link_changeover(n_ptr);
#endif

	/* 
	 * For lost node in own cluster:
	 * - purge all associated name table entries and connections
	 * - trigger similar purge in all other clusters/zones by notifying
	 *   them of disappearance of node
	 *
	 * For lost node in other cluster (or zone):
	 * - withdraw route to failed node
	 */

	if (tipc_mode != TIPC_NET_MODE) {
		/* TODO: THIS IS A HACK TO PREVENT A KERNEL CRASH IF TIPC
		   IS UNLOADED WHEN IT HAS ACTIVE INTER-CLUSTER LINKS;
		   OTHERWISE THE ROUTINES INVOKED VIA SIGNALLING DON'T RUN UNTIL
		   AFTER STUFF THEY DEPEND ON HAS BEEN SHUT DOWN 
		   
		   THE CODE NEEDS TO BE CLEANED UP TO DO THIS BETTER, SINCE
		   FAILING TO RUN THE CLEANUP CODE COULD LEAVE ENTIRES IN THE
		   ROUTING TABLE AND NAME TABLE ... */
		return;
	}

	if (in_own_cluster(n_ptr->elm.addr)) {
		tipc_netsub_notify(&n_ptr->elm, n_ptr->elm.addr);
		tipc_k_signal((Handler)tipc_routetbl_withdraw_node,
			      n_ptr->elm.addr);
	} else {
	       	tipc_k_signal((Handler)tipc_routetbl_withdraw,
			      n_ptr->elm.addr);
	}

	/* Prevent re-contact with node until all cleanup is done */

	n_ptr->cleanup_required = 1;
	tipc_k_signal((Handler)node_cleanup_finished, n_ptr->elm.addr);
}

#if 0
void node_print(struct print_buf *buf, struct tipc_node *n_ptr, char *str)
{
	u32 i;

	tipc_printf(buf, "\n\n%s", str);
	for (i = 0; i < TIPC_MAX_BEARERS; i++) {
		if (!n_ptr->links[i])
			continue;
		tipc_printf(buf, "Links[%u]: %x, ", i, n_ptr->links[i]);
	}
	tipc_printf(buf, "Active links: [%x,%x]\n",
		    n_ptr->active_links[0], n_ptr->active_links[1]);
}
#endif

u32 tipc_available_nodes(const u32 domain)
{
	struct tipc_node *n_ptr;
	u32 cnt = 0;

	read_lock_bh(&tipc_net_lock);
	list_for_each_entry(n_ptr, &nodes_list, node_list) {
		if (!tipc_in_scope(domain, n_ptr->elm.addr))
			continue;
		if (tipc_node_is_up(n_ptr))
			cnt++;
	}
	read_unlock_bh(&tipc_net_lock);
	return cnt;
}

#ifdef CONFIG_TIPC_CONFIG_SERVICE

struct sk_buff *tipc_node_get_nodes(const void *req_tlv_area, int req_tlv_space)
{
	u32 domain;
	struct sk_buff *buf;
	struct tipc_node *n_ptr;
	struct tipc_node_info node_info;
	u32 payload_size;

	if (!TLV_CHECK(req_tlv_area, req_tlv_space, TIPC_TLV_NET_ADDR))
		return tipc_cfg_reply_error_string(TIPC_CFG_TLV_ERROR);

	domain = ntohl(*(__be32 *)TLV_DATA(req_tlv_area));
	if (!tipc_addr_domain_valid(domain))
		return tipc_cfg_reply_error_string(TIPC_CFG_INVALID_VALUE
						   " (network address)");

	read_lock_bh(&tipc_net_lock);
	if (!node_count) {
		read_unlock_bh(&tipc_net_lock);
		return tipc_cfg_reply_none();
	}

	/* Get space for all neighboring nodes */

	payload_size = TLV_SPACE(sizeof(node_info)) * node_count;
	if (payload_size > 32768u) {
		read_unlock_bh(&tipc_net_lock);
		return tipc_cfg_reply_error_string(TIPC_CFG_NOT_SUPPORTED
						   " (too many nodes)");
	}
	buf = tipc_cfg_reply_alloc(payload_size);
	if (!buf) {
		read_unlock_bh(&tipc_net_lock);
		return NULL;
	}

	/* Add TLVs for all nodes in scope */

	list_for_each_entry(n_ptr, &nodes_list, node_list) {
		if (!tipc_in_scope(domain, n_ptr->elm.addr))
			continue;
		node_info.addr = htonl(n_ptr->elm.addr);
		node_info.up = htonl(tipc_node_is_up(n_ptr));
		tipc_cfg_append_tlv(buf, TIPC_TLV_NODE_INFO,
				    &node_info, sizeof(node_info));
	}

	read_unlock_bh(&tipc_net_lock);
	return buf;
}

struct sk_buff *tipc_node_get_links(const void *req_tlv_area, int req_tlv_space)
{
	u32 domain;
	struct sk_buff *buf;
	struct tipc_node *n_ptr;
	struct tipc_link_info link_info;
	u32 payload_size;

	if (!TLV_CHECK(req_tlv_area, req_tlv_space, TIPC_TLV_NET_ADDR))
		return tipc_cfg_reply_error_string(TIPC_CFG_TLV_ERROR);

	domain = ntohl(*(__be32 *)TLV_DATA(req_tlv_area));
	if (!tipc_addr_domain_valid(domain))
		return tipc_cfg_reply_error_string(TIPC_CFG_INVALID_VALUE
						   " (network address)");

	if (tipc_mode != TIPC_NET_MODE)
		return tipc_cfg_reply_none();
	
	read_lock_bh(&tipc_net_lock);

	/* Get space for all unicast links + broadcast link */

	payload_size = TLV_SPACE(sizeof(link_info)) * (link_count + 1);
	if (payload_size > 32768u) {
		read_unlock_bh(&tipc_net_lock);
		return tipc_cfg_reply_error_string(TIPC_CFG_NOT_SUPPORTED
						   " (too many links)");
	}
	buf = tipc_cfg_reply_alloc(payload_size);
	if (!buf) {
		read_unlock_bh(&tipc_net_lock);
		return NULL;
	}

	/* Add TLV for broadcast link */

	link_info.dest = htonl(tipc_own_addr & 0xfffff00);
	link_info.up = htonl(1);
	sprintf(link_info.str, tipc_bclink_name);
	tipc_cfg_append_tlv(buf, TIPC_TLV_LINK_INFO, &link_info, sizeof(link_info));

	/* Add TLVs for any other links in scope */

	list_for_each_entry(n_ptr, &nodes_list, node_list) {
		u32 i;

		if (!tipc_in_scope(domain, n_ptr->elm.addr))
			continue;
		tipc_node_lock(n_ptr);
		for (i = 0; i < TIPC_MAX_BEARERS; i++) {
			if (!n_ptr->links[i])
				continue;
			link_info.dest = htonl(n_ptr->elm.addr);
			link_info.up = htonl(tipc_link_is_up(n_ptr->links[i]));
			strcpy(link_info.str, n_ptr->links[i]->name);
			tipc_cfg_append_tlv(buf, TIPC_TLV_LINK_INFO,
					    &link_info, sizeof(link_info));
		}
		tipc_node_unlock(n_ptr);
	}

	read_unlock_bh(&tipc_net_lock);
	return buf;
}

#endif
