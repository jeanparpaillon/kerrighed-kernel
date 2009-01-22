/*
 * net/tipc/tipc_name_distr.c: TIPC name distribution code
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
#include "tipc_dbg.h"
#include "tipc_link.h"
#include "tipc_msg.h"
#include "tipc_name_distr.h"


/*
 * Distribution list definitions
 */

#define NODE_TO_NODE_LIST	0	/* Item from this node with NODE scope */
#define NODE_TO_CLUSTER_LIST	1	/* Item from this node with CLUSTER scope */
#define NODE_TO_ZONE_LIST	2	/* Item from this node with ZONE scope */
#define NODE_TO_NETWORK_LIST	3	/* Item from this node with NETWORK scope */
#define CLUSTER_TO_CLUSTER_LIST	4	/* Item from rest of cluster with CLUSTER scope */
#define CLUSTER_TO_ZONE_LIST	5	/* Item from rest of cluster with ZONE scope */
#define CLUSTER_TO_NETWORK_LIST	6	/* Item from rest of cluster with NETWORK scope */
#define ZONE_TO_ZONE_LIST	7	/* Item from rest of zone with ZONE scope */
#define ZONE_TO_NETWORK_LIST	8	/* Item from rest of zone with ZONE scope */
#define NETWORK_TO_NETWORK_LIST	9	/* Item from rest of network with NETWORK scope */

#define NUM_DIST_LISTS 10

/*
 * Maximum amount of data in a single bulk item distribution message;
 * helps to avoid fragmentation overhead which might otherwise occur
 */

#define MAX_DIST_MSG_DATA (1500 - LONG_H_SIZE)


typedef struct 
{
	struct list_head list;
	int list_size;
} dist_list_t;
 

/**
 * dist_list_select - determine relevant distribution list for published item
 * @addr: network address of node that published item
 * @scope: scope of publication
 */

static int dist_list_select(u32 addr, u32 scope)
{
	int dist_list_id;

	if (addr_in_node(addr)) {
		if (scope == TIPC_CLUSTER_SCOPE)
			dist_list_id = NODE_TO_CLUSTER_LIST;
		else if (scope == TIPC_ZONE_SCOPE)
			dist_list_id = NODE_TO_ZONE_LIST;
		else if (scope == TIPC_NODE_SCOPE)
			dist_list_id = NODE_TO_NODE_LIST;
		else 
			dist_list_id = NODE_TO_NETWORK_LIST;
	} else if (in_own_cluster(addr)) {
		if (scope == TIPC_CLUSTER_SCOPE)
			dist_list_id = CLUSTER_TO_CLUSTER_LIST;
		else if (scope == TIPC_ZONE_SCOPE)
			dist_list_id = CLUSTER_TO_ZONE_LIST;
		else
			dist_list_id = CLUSTER_TO_NETWORK_LIST;
	} else if (in_own_zone(addr)) {
		if (scope == TIPC_ZONE_SCOPE)
			dist_list_id = ZONE_TO_ZONE_LIST;
		else
			dist_list_id = ZONE_TO_NETWORK_LIST;
	} else {
		dist_list_id = NETWORK_TO_NETWORK_LIST;
	}

	return dist_list_id;
}

/*
 * NAME TABLE CODE
 */

/**
 * struct distr_item - publication info exchanged by TIPC nodes
 * @type: name sequence type
 * @lower: name sequence lower bound
 * @upper: name sequence upper bound
 * @ref: publishing port reference
 * @key: publication key
 * @node: network address of publishing port's node
 * @dist_info: distribution info for name publication
 * 
 * ===> NAME_DISTRIBUTOR message stores fields in network byte order <===
 */

struct name_item {
	u32 type;
	u32 lower;
	u32 upper;
	u32 ref;
	u32 key;
	u32 node;		/* optional */
	u32 dist_info;		/* optional */
};


#define NAME_ITEM_SIZE_UNI 5	/* # words/item for uni-cluster TIPC nodes */
#define NAME_ITEM_SIZE     7	/* # words/item for multi-cluster TIPC nodes */

#define NAME_ITEM_BYTES    (NAME_ITEM_SIZE * sizeof(u32))
#define NAME_ITEMS_MAX     (MAX_DIST_MSG_DATA / NAME_ITEM_BYTES)

/*
 * Name distribution lists
 */

static dist_list_t dist_name_list[NUM_DIST_LISTS] = { 
	{ LIST_HEAD_INIT(dist_name_list[0].list), 0 },
	{ LIST_HEAD_INIT(dist_name_list[1].list), 0 },
	{ LIST_HEAD_INIT(dist_name_list[2].list), 0 },
	{ LIST_HEAD_INIT(dist_name_list[3].list), 0 },
	{ LIST_HEAD_INIT(dist_name_list[4].list), 0 },
	{ LIST_HEAD_INIT(dist_name_list[5].list), 0 },
	{ LIST_HEAD_INIT(dist_name_list[6].list), 0 },
	{ LIST_HEAD_INIT(dist_name_list[7].list), 0 },
	{ LIST_HEAD_INIT(dist_name_list[8].list), 0 },
	{ LIST_HEAD_INIT(dist_name_list[9].list), 0 },
	};

/**
 * name_to_item - convert distributed publication to name item
 */

static void name_to_item(struct publication *publ, int dist_mask,
			 unchar *item, int item_size)
{
	struct name_item *i = (struct name_item *)item;

	i->type = htonl(publ->type);
	i->lower = htonl(publ->lower);
	i->upper = htonl(publ->upper);
	i->ref = htonl(publ->ref);
	i->key = htonl(publ->key);

	if (item_size >= NAME_ITEM_SIZE) {
		i->dist_info = htonl(publ->scope | (dist_mask << 4));
		i->node = htonl(publ->node);
	}
}

/**
 * item_to_name - convert name item to distributed publication
 */

static void item_to_name(struct publication *publ, int *dist_mask,
			 unchar *item, int item_size)
{
	struct name_item *i = (struct name_item *)item;

	publ->type = ntohl(i->type);
	publ->lower = ntohl(i->lower);
	publ->upper = ntohl(i->upper);
	publ->ref = ntohl(i->ref);
	publ->key = ntohl(i->key);

	if (item_size >= NAME_ITEM_SIZE) {
		publ->node = ntohl(i->node);
		publ->scope = ntohl(i->dist_info);
		*dist_mask = (publ->scope >> 4) & 0xF;
		publ->scope &= 0xF;
	}
}

/**
 * named_prepare_buf - allocate & initialize a name info message
 */

static struct sk_buff *named_prepare_buf(u32 type, u32 num_items, int item_size, 
					 u32 dest)
{
	u32 size = LONG_H_SIZE + num_items * (item_size * sizeof(u32));
	struct sk_buff *buf = buf_acquire(size);  
	struct tipc_msg *msg;

	if (buf != NULL) {
		msg = buf_msg(buf);
		tipc_msg_init(msg, NAME_DISTRIBUTOR, type, LONG_H_SIZE, dest);
		msg_set_size(msg, size);
		msg_set_item_size(msg, item_size);
	}
	return buf;
}

/**
 * tipc_named_insert_publ - add name to appropriate distribution list
 */

void tipc_named_insert_publ(struct publication *publ)
{
	int dist_list_id;

	dist_list_id = dist_list_select(publ->node, publ->scope);

	list_add_tail(&publ->distr_list, &dist_name_list[dist_list_id].list);
	dist_name_list[dist_list_id].list_size++;
}

/**
 * tipc_named_remove_publ - remove name from its distribution list
 */

void tipc_named_remove_publ(struct publication *publ)
{
	int dist_list_id;

	dist_list_id = dist_list_select(publ->node, publ->scope);

	list_del(&publ->distr_list);
	dist_name_list[dist_list_id].list_size--;
}

/**
 * named_distribute - prepare name info for distribution to another node
 */

static void named_distribute(struct list_head *delivery_list, u32 dest_node,
			     int dist_list_id, int dist_mask, int item_size)
{
	struct publication *publ;
	struct sk_buff *buf = NULL;
	unchar *item = NULL;
	u32 buf_todo_items = 0;
	u32 name_items_max = MAX_DIST_MSG_DATA / (item_size * sizeof(u32));
	int list_cnt;

	list_cnt = dist_name_list[dist_list_id].list_size;

	list_for_each_entry(publ, &dist_name_list[dist_list_id].list,
			    distr_list) {
		if (buf == NULL) {
			buf_todo_items = (list_cnt <= name_items_max) ?
				list_cnt : name_items_max;
			buf = named_prepare_buf(DIST_PUBLISH, buf_todo_items, 
						item_size, dest_node);       
			if (!buf) {
				warn("Bulk publication failure\n");
				return;
			}
			list_cnt -= buf_todo_items;
			item = msg_data(buf_msg(buf));
		}
		name_to_item(publ, dist_mask, item, item_size);
		item += (item_size * sizeof(u32));
		if (--buf_todo_items == 0) {
			msg_set_link_selector(buf_msg(buf), (dest_node & 1));
			list_add_tail((struct list_head *)buf, delivery_list);
			buf = NULL;
		}
	}
	dbg_assert(buf == NULL);
}

/**
 * tipc_named_node_up - tell specified node about relevant name info
 */

void tipc_named_node_up(unsigned long node)
{
	struct sk_buff *buf;
	struct sk_buff *temp_buf;
	struct list_head delivery_list;

	INIT_LIST_HEAD(&delivery_list);

	read_lock_bh(&tipc_nametbl_lock); 

	if (in_own_cluster(node)) {
		named_distribute(&delivery_list, node, NODE_TO_CLUSTER_LIST,
				 0, NAME_ITEM_SIZE);
		named_distribute(&delivery_list, node, NODE_TO_ZONE_LIST,
				 TIPC_DIST_TO_ZONE, NAME_ITEM_SIZE);
		named_distribute(&delivery_list, node, NODE_TO_NETWORK_LIST,
				 TIPC_DIST_TO_NETWORK | TIPC_DIST_TO_ZONE,
				 NAME_ITEM_SIZE);
		if (tipc_own_routes > 0) {
			named_distribute(&delivery_list, node, ZONE_TO_ZONE_LIST,
					 0, NAME_ITEM_SIZE);
			named_distribute(&delivery_list, node, ZONE_TO_NETWORK_LIST,
					 TIPC_DIST_TO_NETWORK, NAME_ITEM_SIZE);
			named_distribute(&delivery_list, node, NETWORK_TO_NETWORK_LIST,
					 TIPC_DIST_TO_ZONE, NAME_ITEM_SIZE);
		}
	} else if (in_own_zone(node)) {
		named_distribute(&delivery_list, node, NODE_TO_ZONE_LIST,
				 TIPC_DIST_TO_CLUSTER, NAME_ITEM_SIZE);
		named_distribute(&delivery_list, node, NODE_TO_NETWORK_LIST,
				 TIPC_DIST_TO_NETWORK | TIPC_DIST_TO_CLUSTER,
				 NAME_ITEM_SIZE);
		named_distribute(&delivery_list, node, CLUSTER_TO_ZONE_LIST,
				 TIPC_DIST_TO_CLUSTER, NAME_ITEM_SIZE);
		named_distribute(&delivery_list, node, CLUSTER_TO_NETWORK_LIST,
				 TIPC_DIST_TO_NETWORK | TIPC_DIST_TO_CLUSTER,
				 NAME_ITEM_SIZE);
		named_distribute(&delivery_list, node, NETWORK_TO_NETWORK_LIST,
				 TIPC_DIST_TO_CLUSTER, NAME_ITEM_SIZE);
	} else /* node is in another zone */ {
		named_distribute(&delivery_list, node, NODE_TO_NETWORK_LIST,
				 TIPC_DIST_TO_ZONE | TIPC_DIST_TO_CLUSTER,
				 NAME_ITEM_SIZE);
		named_distribute(&delivery_list, node, CLUSTER_TO_NETWORK_LIST,
				 TIPC_DIST_TO_ZONE | TIPC_DIST_TO_CLUSTER,
				 NAME_ITEM_SIZE);
		named_distribute(&delivery_list, node, ZONE_TO_NETWORK_LIST,
				 TIPC_DIST_TO_ZONE | TIPC_DIST_TO_CLUSTER,
				 NAME_ITEM_SIZE);
	}

	read_unlock_bh(&tipc_nametbl_lock); 

	list_for_each_safe(buf, temp_buf, ((struct sk_buff *)&delivery_list)) {
		list_del((struct list_head *)buf);
		if (tipc_link_send(buf, node, node) < 0) {
			warn("Bulk publication not sent\n");
		}
	}
}

/**
 * tipc_named_node_up_uni - tell uni-cluster node about relevant name info
 */

void tipc_named_node_up_uni(unsigned long node)
{
#ifdef CONFIG_TIPC_UNICLUSTER_FRIENDLY
	struct sk_buff *buf;
	struct sk_buff *temp_buf;
	struct list_head delivery_list;

	INIT_LIST_HEAD(&delivery_list);

	read_lock_bh(&tipc_nametbl_lock); 

	named_distribute(&delivery_list, node, NODE_TO_CLUSTER_LIST,
			 0, NAME_ITEM_SIZE_UNI);
	named_distribute(&delivery_list, node, NODE_TO_ZONE_LIST,
			 0, NAME_ITEM_SIZE_UNI);
	named_distribute(&delivery_list, node, NODE_TO_NETWORK_LIST,
			 0, NAME_ITEM_SIZE_UNI);

	read_unlock_bh(&tipc_nametbl_lock); 

	list_for_each_safe(buf, temp_buf, ((struct sk_buff *)&delivery_list)) {
		list_del((struct list_head *)buf);
		if (tipc_link_send(buf, node, node) < 0) {
			warn("Bulk publication not sent\n");
		}
	}
#endif
}

/**
 * named_cluster_distribute - send name to all adjacent cluster nodes
 */

static void named_cluster_distribute(struct publication *publ, int msg_type,
				     int dist_mask)
{
	struct sk_buff *buf;

	dist_mask &= ~TIPC_DIST_TO_CLUSTER;

	buf = named_prepare_buf(msg_type, 1, NAME_ITEM_SIZE, tipc_addr(0, 0, 0));
	if (!buf) {
		warn("Memory squeeze; failed to distribute publication\n");
		return;
	}

	name_to_item(publ, dist_mask, msg_data(buf_msg(buf)), NAME_ITEM_SIZE);

#ifdef CONFIG_TIPC_UNICLUSTER_FRIENDLY
	/*
	 * Hide name from to cluster's uni-cluster nodes if it was
	 * issued by another node, since they are unable to deal with
	 * name messages originating outside their own cluster (and would
	 * think this node is the originator!) 
	 */

	if (publ->node != tipc_own_addr) {
		struct sk_buff *buf_copy;
		struct tipc_node *n_ptr;
		int i;

		for (i = 0; i < tipc_local_nodes.first_free; i++) {
			n_ptr = (struct tipc_node *)tipc_local_nodes.element[i];
			if (!tipc_node_is_up(n_ptr) || 
			    (n_ptr->flags & NF_MULTICLUSTER) == 0)
				continue;

			buf_copy = skb_copy(buf, GFP_ATOMIC);
			if (buf_copy == NULL) {
				warn("Publication distribution to cluster failed\n");
				break;
			}
			msg_set_destnode(buf_msg(buf_copy),
					 n_ptr->elm.addr);
			if (tipc_link_send(buf_copy, n_ptr->elm.addr, 
					   n_ptr->elm.addr) < 0) {
				warn("Publication distribution to cluster failed\n");
			}
		}

		buf_discard(buf);
		return;
	}
#endif

	/*
	 * Broadcast name to all nodes in own cluster
	 *
	 * Note: Uni-cluster nodes will ignore the extra fields at the end
	 * of the lone name item, so the "new style" form is OK here
	 */

	if (tipc_bclink_send_msg(buf) < 0) {
		warn("Publication distribution to cluster failed\n");
	}
}

/**
 * named_zone_distribute - send name to all adjacent clusters in zone
 */

static void named_zone_distribute(struct publication *publ, int msg_type,
				  int dist_mask)
{
	struct sk_buff *buf;
	u32 router;
	int i;

	dist_mask &= ~TIPC_DIST_TO_ZONE;
	dist_mask |= TIPC_DIST_TO_CLUSTER;

	for (i = 0; i < tipc_remote_nodes.first_free; i++) {
		router = tipc_remote_nodes.element[i]->addr;

		if (!in_own_zone(router))
			continue;
		if (!tipc_node_is_up(
			(struct tipc_node *)tipc_remote_nodes.element[i]))
			continue;

		buf = named_prepare_buf(msg_type, 1, NAME_ITEM_SIZE, router);
		if (!buf) {
			warn("Memory squeeze; failed to distribute name table msg\n");
			break;
		}
		name_to_item(publ, dist_mask, msg_data(buf_msg(buf)), NAME_ITEM_SIZE);
		if (tipc_link_send(buf, router, router) < 0) {
			warn("Failed to distribute name table msg\n");
		}
	}
}

/**
 * named_network_distribute - send name to all neighboring zones in network
 */

static void named_network_distribute(struct publication *publ, int msg_type,
				     int dist_mask)
{
	struct sk_buff *buf;
	u32 router;
	int i;

	dist_mask &= ~TIPC_DIST_TO_NETWORK;
	dist_mask |= (TIPC_DIST_TO_ZONE | TIPC_DIST_TO_CLUSTER);

	for (i = 0; i < tipc_remote_nodes.first_free; i++) {
		router = tipc_remote_nodes.element[i]->addr;

		if (in_own_zone(router))
			continue;
		if (!tipc_node_is_up(
			(struct tipc_node *)tipc_remote_nodes.element[i]))
			continue;

		buf = named_prepare_buf(msg_type, 1, NAME_ITEM_SIZE, router);
		if (!buf) {
			warn("Memory squeeze; failed to distribute name table msg\n");
			break;
		}
		name_to_item(publ, dist_mask, msg_data(buf_msg(buf)), NAME_ITEM_SIZE);
		if (tipc_link_send(buf, router, router) < 0) {
			warn("Failed to distribute name table msg\n");
		}
	}
}


/**
 * tipc_named_distribute - send name info to relevant nodes
 */

void tipc_named_distribute(struct publication *publ, int msg_type,
			   int dist_mask)
{
	if (tipc_mode != TIPC_NET_MODE)
		return;

	if (dist_mask & TIPC_DIST_TO_CLUSTER) {
		named_cluster_distribute(publ, msg_type, dist_mask);
	}
	if (dist_mask & TIPC_DIST_TO_ZONE) {
		named_zone_distribute(publ, msg_type, dist_mask);
	}
	if (dist_mask & TIPC_DIST_TO_NETWORK) {
		named_network_distribute(publ, msg_type, dist_mask);
	}
}

/**
 * named_purge_publ - delete name associated with a failed node/region
 * 
 * Invoked for each name that can no longer be reached.  
 * Removes publication structure from name table & deletes it.
 * In rare cases the link may have come back up again when this
 * function is called, and we have two items representing the same
 * publication. Nudge this item's key to distinguish it from the other.
 *
 * Publication's network element subscription is already unsubscribed, 
 * so we don't have to do that here ...
 */

static void named_purge_publ(struct publication *publ)
{
	write_lock_bh(&tipc_nametbl_lock);

	publ->key += 1222345;
	publ = tipc_nametbl_remove_publ(publ->type, publ->lower, 
					publ->node, publ->ref, publ->key);
	if (publ != NULL) {
		tipc_named_remove_publ(publ);
	}

	write_unlock_bh(&tipc_nametbl_lock);

	kfree(publ);
}

/**
 * tipc_named_recv - process name table update message sent by another node
 */

void tipc_named_recv(struct sk_buff *buf)
{
	struct publication publ_info;
	struct publication *publ;
	struct tipc_msg *msg = buf_msg(buf);
	u32 type = msg_type(msg);
	unchar *item = msg_data(msg);
	int item_size = msg_item_size(msg);
	int item_size_min = NAME_ITEM_SIZE;
	u32 item_count;
	int dist_mask;

#ifdef CONFIG_TIPC_UNICLUSTER_FRIENDLY
	if (item_size == 0) {
		item_size = NAME_ITEM_SIZE_UNI;
		item_size_min = NAME_ITEM_SIZE_UNI;
		publ_info.node = msg_orignode(msg);
		publ_info.scope = TIPC_CLUSTER_SCOPE;
		dist_mask = 0;
	}
#endif

	if (item_size < item_size_min) {
		warn("Invalid name table item received\n");
		item_count = 0;
	} else {
		item_count = msg_data_sz(msg) / (item_size * sizeof(u32));
	}

	while (item_count--) {

		item_to_name(&publ_info, &dist_mask, item, item_size);

		if (type == DIST_PUBLISH) {
			write_lock_bh(&tipc_nametbl_lock); 
			publ = tipc_nametbl_insert_publ(publ_info.type, 
							publ_info.lower,
							publ_info.upper,
							publ_info.scope,
							publ_info.node,
							publ_info.ref,
							publ_info.key);
			if (publ) {
				tipc_netsub_bind(&publ->subscr, publ->node,
						 (net_ev_handler)named_purge_publ,
						 publ);
				tipc_named_insert_publ(publ);
			}
			write_unlock_bh(&tipc_nametbl_lock);

			/* TODO: Is there a slight risk that, on an SMP system,
			   another CPU could remove the publication (due to a
			   route withdrawl, triggered by a link timeout) and 
			   send a withdraw message for it before we send the
			   associated publish message? (The risk seems small,
			   but could it happen???) To lessen the impact of
			   such a situation, we use a copy of the publication
			   info, but this still means that there is a chance
			   of messages being delivered in the wrong order.
			   We probably need to ensure that distribution of
			   name (& route) messages is single threaded to
			   eliminate this risk ... */

			if (publ) {
				if (dist_mask)
					tipc_named_distribute(&publ_info,
							      DIST_PUBLISH,
							      dist_mask);
			}
		}
		else if (type == DIST_WITHDRAW) {
			write_lock_bh(&tipc_nametbl_lock); 
			publ = tipc_nametbl_remove_publ(publ_info.type,
							publ_info.lower,
							publ_info.node,
							publ_info.ref,
							publ_info.key);

			if (publ) {
				tipc_netsub_unbind(&publ->subscr);
				tipc_named_remove_publ(publ);
			}
			write_unlock_bh(&tipc_nametbl_lock); 
			if (publ) {
				if (dist_mask)
					tipc_named_distribute(publ,
							      DIST_WITHDRAW,
							      dist_mask);
				kfree(publ);
			}
		}
		else {
			dbg("Unrecognized name table message received\n");
		}

		item += (item_size * sizeof(u32));
	}
	buf_discard(buf);
}

/**
 * tipc_named_reinit - update name table entries to reflect new node address
 * 
 * This routine is called when TIPC enters networking mode.
 * All names currently published by this node are updated to reflect
 * the node's new network address.
 */

void tipc_named_reinit(void)
{
	struct publication *publ;

	write_lock_bh(&tipc_nametbl_lock); 
	list_for_each_entry(publ,
			    &dist_name_list[NODE_TO_NODE_LIST].list,
			    distr_list) {
		publ->node = tipc_own_addr;
	}
	list_for_each_entry(publ,
			    &dist_name_list[NODE_TO_CLUSTER_LIST].list,
			    distr_list) {
		publ->node = tipc_own_addr;
	}
	list_for_each_entry(publ,
			    &dist_name_list[NODE_TO_ZONE_LIST].list,
			    distr_list) {
		publ->node = tipc_own_addr;
	}
	write_unlock_bh(&tipc_nametbl_lock); 
}

/*
 * ROUTING TABLE CODE
 */

/**
 * struct route_item - route info exchanged by TIPC nodes
 * @remote_region: network address of region reachable by route
 * @local_router: network address of node publishing route
 * @remote_router: network address of node route connects to
 * @dist_info: distribution info for route publication
 * 
 * ===> ROUTE_DISTRIBUTOR message stores fields in network byte order <===
 */

struct route_item {
	u32 remote_region;
	u32 local_router;
	u32 remote_router;
	u32 dist_info;
};

#define ROUTE_ITEM_SIZE     4
#define ROUTE_ITEM_BYTES    (ROUTE_ITEM_SIZE * sizeof(u32))
#define ROUTE_ITEMS_MAX     (MAX_DIST_MSG_DATA / ROUTE_ITEM_BYTES)

/*
 * Route distribution lists
 *
 * Note: some lists are currently unused, since routes are only published
 *       with "cluster" or "zone" scope at the moment
 */

static dist_list_t dist_route_list[NUM_DIST_LISTS] = { 
	{ LIST_HEAD_INIT(dist_route_list[0].list), 0 },
	{ LIST_HEAD_INIT(dist_route_list[1].list), 0 },
	{ LIST_HEAD_INIT(dist_route_list[2].list), 0 },
	{ LIST_HEAD_INIT(dist_route_list[3].list), 0 },
	{ LIST_HEAD_INIT(dist_route_list[4].list), 0 },
	{ LIST_HEAD_INIT(dist_route_list[5].list), 0 },
	{ LIST_HEAD_INIT(dist_route_list[6].list), 0 },
	{ LIST_HEAD_INIT(dist_route_list[7].list), 0 },
	{ LIST_HEAD_INIT(dist_route_list[8].list), 0 },
	{ LIST_HEAD_INIT(dist_route_list[9].list), 0 },
	};


/**
 * route_to_item - convert distributed publication to route item
 */

static void route_to_item(struct publication *publ, int dist_mask, unchar *item)
{
	struct route_item *i = (struct route_item *)item;

	i->remote_region = htonl(publ->lower);
	i->local_router = htonl(publ->node);
	i->remote_router = htonl(publ->ref);
	i->dist_info = htonl(publ->scope | (dist_mask << 4));
}

/**
 * item_to_route - convert route item to distributed publication
 */

static void item_to_route(struct publication *publ, int *dist_mask,
			  unchar *item, int item_size)
{
	struct route_item *i = (struct route_item *)item;

	publ->type = TIPC_ROUTE;
	publ->lower = ntohl(i->remote_region);
	publ->upper = publ->lower;
	publ->node = ntohl(i->local_router);
	publ->ref = ntohl(i->remote_router);
	publ->key = 0;
	publ->scope = ntohl(i->dist_info);
	*dist_mask = (publ->scope >> 4) & 0xF;
	publ->scope &= 0xF;
}

/**
 * route_prepare_buf - allocate & initialize a route info message
 */

static struct sk_buff *route_prepare_buf(u32 type, u32 num_items, u32 dest)
{
	u32 size = LONG_H_SIZE + (num_items * ROUTE_ITEM_BYTES);
	struct sk_buff *buf = buf_acquire(size);  
	struct tipc_msg *msg;

	if (buf != NULL) {
		msg = buf_msg(buf);
		tipc_msg_init(msg, ROUTE_DISTRIBUTOR, type, LONG_H_SIZE, dest);
		msg_set_size(msg, size);
		msg_set_item_size(msg, ROUTE_ITEM_SIZE);
	}
	return buf;
}


/**
 * tipc_route_insert_publ - add route to appropriate distribution list
 */

void tipc_route_insert_publ(struct publication *publ)
{
	int dist_list_id;

	dist_list_id = dist_list_select(publ->node, publ->scope);
	
	list_add_tail(&publ->distr_list, &dist_route_list[dist_list_id].list);
	dist_route_list[dist_list_id].list_size++;
}

/**
 * tipc_route_remove_publ - remove route from its distribution list
 */

void tipc_route_remove_publ(struct publication *publ)
{
	int dist_list_id;

	dist_list_id = dist_list_select(publ->node, publ->scope);
	
	list_del(&publ->distr_list);
	dist_route_list[dist_list_id].list_size--;
}

/**
 * route_distribute - prepare route info for distribution to another node
 */

static void route_distribute(struct list_head *delivery_list, u32 dest_node,
			     int dist_list_id, int dist_mask)
{
	struct publication *publ;
	struct sk_buff *buf = NULL;
	unchar *item = NULL;
	u32 buf_todo_items = 0;
	int list_cnt = dist_route_list[dist_list_id].list_size;

	list_for_each_entry(publ, &dist_route_list[dist_list_id].list,
			    distr_list) {
		if (buf == NULL) {
			buf_todo_items = (list_cnt <= ROUTE_ITEMS_MAX) ?
				list_cnt : ROUTE_ITEMS_MAX;
			buf = route_prepare_buf(DIST_PUBLISH, buf_todo_items, 
						dest_node);       
			if (!buf) {
				warn("Bulk route publication failure\n");
				return;
			}
			list_cnt -= buf_todo_items;
			item = msg_data(buf_msg(buf));
		}
		route_to_item(publ, dist_mask, item);
		item += ROUTE_ITEM_BYTES;
		if (--buf_todo_items == 0) {
			msg_set_link_selector(buf_msg(buf), (dest_node & 1));
			list_add_tail((struct list_head *)buf, delivery_list);
			buf = NULL;
		}
	}
	dbg_assert(buf == NULL);
}

/**
 * tipc_route_node_up - tell specified node about relevant routes
 */

void tipc_route_node_up(unsigned long node)
{
	struct sk_buff *buf;
	struct sk_buff *temp_buf;
	struct list_head delivery_list;

	INIT_LIST_HEAD(&delivery_list);

	read_lock_bh(&tipc_routetbl_lock); 

	if (in_own_cluster(node)) {
		route_distribute(&delivery_list, node, NODE_TO_CLUSTER_LIST,
				 0);
		route_distribute(&delivery_list, node, NODE_TO_ZONE_LIST,
				 TIPC_DIST_TO_ZONE);
		if (tipc_own_routes > 0) {
			route_distribute(&delivery_list, node, ZONE_TO_ZONE_LIST,
					 0);
		}
	} else { /* in_own_zone(node) */
		route_distribute(&delivery_list, node, NODE_TO_ZONE_LIST,
				 TIPC_DIST_TO_CLUSTER);
		route_distribute(&delivery_list, node, CLUSTER_TO_ZONE_LIST,
				 TIPC_DIST_TO_CLUSTER);
	}

	read_unlock_bh(&tipc_routetbl_lock);

	list_for_each_safe(buf, temp_buf, ((struct sk_buff *)&delivery_list)) {
		list_del((struct list_head *)buf);
		if (tipc_link_send(buf, node, node) < 0) {
			warn("Bulk route update not sent\n");
		}
	}
}

/**
 * route_cluster_distribute - send route to all neighboring cluster nodes
 * 
 * Note: Pre-TIPC 1.7 nodes will ignore routing info messages
 */

static void route_cluster_distribute(struct publication *publ, int msg_type,
				     int dist_mask)
{
	struct sk_buff *buf;

	dist_mask &= ~TIPC_DIST_TO_CLUSTER;

	buf = route_prepare_buf(msg_type, 1, tipc_addr(0, 0, 0));
	if (!buf) {
		warn("Memory squeeze; failed to distribute route\n");
		return;
	}

	route_to_item(publ, dist_mask, msg_data(buf_msg(buf)));

	if (tipc_bclink_send_msg(buf) < 0) {
		warn("Route distribution to cluster failed\n");
	}
}

/**
 * route_zone_distribute - send route to all neighboring clusters in zone
 */

static void route_zone_distribute(struct publication *publ, int msg_type,
				  int dist_mask)
{
	struct sk_buff *buf;
	u32 router;
	int i;

	dist_mask &= ~TIPC_DIST_TO_ZONE;
	dist_mask |= TIPC_DIST_TO_CLUSTER;

	for (i = 0; i < tipc_remote_nodes.first_free; i++) {
		router = tipc_remote_nodes.element[i]->addr;

		if (!in_own_zone(router))
			continue;
		if (!tipc_node_is_up(
			(struct tipc_node *)tipc_remote_nodes.element[i]))
			continue;

		buf = route_prepare_buf(msg_type, 1, router);
		if (!buf) {
			warn("Memory squeeze; failed to distribute route msg\n");
			break;
		}
		route_to_item(publ, dist_mask, msg_data(buf_msg(buf)));
		if (tipc_link_send(buf, router, router) < 0) {
			warn("Failed to distribute route msg\n");
		}
	}
}

/**
 * route_network_distribute - send route to all neighboring zones in network
 */

static void route_network_distribute(struct publication *publ, int msg_type,
				     int dist_mask)
{
	struct sk_buff *buf;
	u32 router;
	int i;

	dist_mask &= ~TIPC_DIST_TO_NETWORK;
	dist_mask |= (TIPC_DIST_TO_ZONE | TIPC_DIST_TO_CLUSTER);

	for (i = 0; i < tipc_remote_nodes.first_free; i++) {
		router = tipc_remote_nodes.element[i]->addr;

		if (in_own_zone(router))
			continue;
		if (!tipc_node_is_up(
			(struct tipc_node *)tipc_remote_nodes.element[i]))
			continue;

		buf = route_prepare_buf(msg_type, 1, router);
		if (!buf) {
			warn("Memory squeeze; failed to distribute route msg\n");
			break;
		}
		route_to_item(publ, dist_mask, msg_data(buf_msg(buf)));
		if (tipc_link_send(buf, router, router) < 0) {
			warn("Failed to distribute route msg\n");
		}
	}
}

/**
 * tipc_route_distribute - send route info to relevant nodes
 */

void tipc_route_distribute(struct publication *publ, int msg_type,
			   int dist_mask)
{
	if (dist_mask & TIPC_DIST_TO_CLUSTER) {
		route_cluster_distribute(publ, msg_type, dist_mask);
	}
	if (dist_mask & TIPC_DIST_TO_ZONE) {
		route_zone_distribute(publ, msg_type, dist_mask);
	}
	if (dist_mask & TIPC_DIST_TO_NETWORK) {
		route_network_distribute(publ, msg_type, dist_mask);
	}
}

/**
 * route_purge_publ - delete route associated with a failed node/region
 * 
 * Invoked for each route that can no longer be reached.  
 * Removes publication structure from route table & deletes it.
 * In rare cases the link may have come back up again when this
 * function is called, and we have two items representing the same
 * publication. Nudge this item's key to distinguish it from the other.
 *
 * Publication's network element subscription is already unsubscribed, 
 * so we don't have to do that here ...
 */

static void route_purge_publ(struct publication *publ)
{
	write_lock_bh(&tipc_routetbl_lock);

	publ->key += 1222345;
	publ = tipc_nameseq_remove_publ(route_table,publ->lower, 
					publ->node, publ->ref, publ->key);
	if (publ != NULL) {
		tipc_all_routes--;
		tipc_route_remove_publ(publ);
	}

	write_unlock_bh(&tipc_routetbl_lock);

	kfree(publ);
}

/**
 * tipc_route_recv - process routing table message sent by another node
 */

void tipc_route_recv(struct sk_buff *buf)
{
	struct publication publ_info;
	struct publication *publ;
	struct tipc_msg *msg = buf_msg(buf);
	u32 type = msg_type(msg);
	unchar *item = msg_data(msg);
	int item_size = msg_item_size(msg);
	u32 item_count;
	int dist_mask;

	if (item_size < ROUTE_ITEM_SIZE) {
		warn("Invalid routing table item received\n");
		item_count = 0;
	} else {
		item_count = msg_data_sz(msg) / (item_size * sizeof(u32));
	}

	while (item_count--) {

		item_to_route(&publ_info, &dist_mask, item, item_size);

		if (type == DIST_PUBLISH) {
			write_lock_bh(&tipc_routetbl_lock);
			publ = tipc_nameseq_insert_publ(route_table, 
							TIPC_ROUTE, 
							publ_info.lower, 
							publ_info.upper,
							publ_info.scope,
							publ_info.node, 
							publ_info.ref, 
							publ_info.key);
			if (publ) {
				tipc_netsub_bind(&publ->subscr, publ->node,
						 (net_ev_handler)route_purge_publ,
						 publ);
				tipc_all_routes++;
				tipc_route_insert_publ(publ);
			}
			write_unlock_bh(&tipc_routetbl_lock);
			/* TODO: See comment in corresponding place in
			         tipc_named_recv(); it applies here too */
			if (publ) {
				if (dist_mask) {
					tipc_route_distribute(&publ_info,
							      DIST_PUBLISH,
							      dist_mask);
				}
			}
		}
		else if (type == DIST_WITHDRAW) {
			write_lock_bh(&tipc_routetbl_lock); 
			publ = tipc_nameseq_remove_publ(route_table,
							publ_info.lower,
							publ_info.node, 
							publ_info.ref, 
							publ_info.key);
			if (publ) {
				tipc_netsub_unbind(&publ->subscr);
				tipc_all_routes--;
				tipc_route_remove_publ(publ);
			}
			write_unlock_bh(&tipc_routetbl_lock); 
			if (publ) {
				if (dist_mask) {
					tipc_route_distribute(publ,
							      DIST_WITHDRAW,
							      dist_mask);
				}
				kfree(publ);
			}
		}
		else if (type == DIST_PURGE) {
			write_lock_bh(&tipc_routetbl_lock); 
			tipc_routetbl_purge(publ_info.lower);
			write_unlock_bh(&tipc_routetbl_lock);

			if (dist_mask) {
				tipc_route_distribute(&publ_info,
						      DIST_PURGE,
						      dist_mask);
			}
		} 
		else {
			dbg("Unrecognized routing table message received\n");
		}

		item += (item_size * sizeof(u32));
	}
	buf_discard(buf);
}

