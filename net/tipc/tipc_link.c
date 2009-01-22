/*
 * net/tipc/tipc_link.c: TIPC link code
 *
 * Copyright (c) 1996-2007, Ericsson AB
 * Copyright (c) 2004-2008, Wind River Systems
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
#include "tipc_net.h"
#include "tipc_node.h"
#include "tipc_port.h"
#include "tipc_addr.h"
#include "tipc_name_distr.h"
#include "tipc_bearer.h"
#include "tipc_name_table.h"
#include "tipc_discover.h"
#include "tipc_cfgsrv.h"
#include "tipc_bcast.h"


/*
 * Out-of-range value for link session numbers
 */

#define INVALID_SESSION 0x10000

/*
 * Limit for deferred reception queue:
 */

#define DEF_QUEUE_LIMIT 256u

/*
 * Link state events:
 */

#define  STARTING_EVT    856384768	/* link processing trigger */
#define  TRAFFIC_MSG_EVT 560815u	/* rx'd ??? */
#define  TIMEOUT_EVT     560817u	/* link timer expired */

/*
 * The following two 'message types' is really just implementation
 * data conveniently stored in the message header.
 * They must not be considered part of the protocol
 */
#define OPEN_MSG   0
#define CLOSED_MSG 1

/*
 * State value stored in 'exp_msg_count'
 */

#define START_CHANGEOVER 100000u

/**
 * struct link_name - deconstructed link name
 * @addr_local: network address of node at this end
 * @if_local: name of interface at this end
 * @addr_peer: network address of node at far end
 * @if_peer: name of interface at far end
 */

struct link_name {
	u32 addr_local;
	char if_local[TIPC_MAX_IF_NAME];
	u32 addr_peer;
	char if_peer[TIPC_MAX_IF_NAME];
};

/*
 * Global counter of fragmented messages issued by node
 */

static atomic_t link_fragm_msg_no = ATOMIC_INIT(0);


static void link_handle_out_of_seq_msg(struct link *l_ptr,
				       struct sk_buff *buf);
static void link_recv_proto_msg(struct link *l_ptr, struct sk_buff *buf);
static int  link_recv_changeover_msg(struct link **l_ptr, struct sk_buff **buf);
static void link_set_supervision_props(struct link *l_ptr, u32 tolerance);
static int  link_send_sections_long(struct port *sender,
				    struct iovec const *msg_sect,
				    u32 num_sect, u32 destnode);
static void link_check_defragm_bufs(struct link *l_ptr);
static void link_state_event(struct link *l_ptr, u32 event);
static void link_reset_statistics(struct link *l_ptr);


/*
 * Debugging code used by link routines only
 *
 * When debugging link problems on a system that has multiple links,
 * the standard TIPC debugging routines may not be useful since they
 * allow the output from multiple links to be intermixed.  For this reason
 * routines of the form "dbg_link_XXX()" have been created that will capture
 * debug info into a link's personal print buffer, which can then be dumped
 * to the system console upon request.
 *
 * To utilize the dbg_link_XXX() routines:
 * - set LINK_LOG_BUF_SIZE to the size of a link's print buffer 
 *   (must be at least TIPC_PB_MIN_SIZE)
 * - set DBG_OUTPUT_LINK where needed to indicate where the debug output
 *   should be directed (see example below)
 *
 * Notes:
 * - "l_ptr" must be valid when using dbg_link_XXX() routines
 * - when debugging a system that has only one link, it may be easier to set
 *   LINK_LOG_BUF_SIZE to 0 and simply point DBG_OUTPUT_LINK to the system
 *   console or TIPC's log buffer (see example below)
 * - it may also be sufficient in some situations to use TIPC's standard
 *   debugging routines and control the debugging output using DBG_OUTPUT
 */

#define LINK_LOG_BUF_SIZE 0

/*
 * DBG_OUTPUT_LINK is the destination print buffer chain for per-link debug
 * messages.  It defaults to the the null print buffer, but can be enabled
 * where needed to allow debug messages to be selectively generated.
 */

#define DBG_OUTPUT_LINK TIPC_NULL
#if 0
#define DBG_OUTPUT_LINK (&l_ptr->print_buf)
#define DBG_OUTPUT_LINK TIPC_LOG
#define DBG_OUTPUT_LINK TIPC_CONS
#endif

#ifdef CONFIG_TIPC_DEBUG

#define dbg_link(fmt, arg...)	   dbg_printf(DBG_OUTPUT_LINK, fmt, ##arg)
#define dbg_link_msg(msg, txt)	   dbg_msg(DBG_OUTPUT_LINK, msg, txt)
#define dbg_link_dump(fmt, arg...) dbg_dump(DBG_OUTPUT_LINK, fmt, ##arg)
#define dbg_link_state(txt)	\
	do {if (DBG_OUTPUT_LINK != TIPC_NULL) \
		{tipc_printf(DBG_OUTPUT_LINK, txt); \
		 dbg_print_link_state(DBG_OUTPUT_LINK, l_ptr);} \
	} while(0)

static void dbg_print_link_state(struct print_buf *buf, struct link *l_ptr);
static void dbg_print_link(struct link *l_ptr, const char *str);
static void dbg_print_buf_chain(struct sk_buff *root_buf);

#else

#define dbg_link(fmt, arg...)	       	do {} while (0)
#define dbg_link_msg(msg, txt)	       	do {} while (0)
#define dbg_link_dump(fmt, arg...)	do {} while (0)
#define dbg_link_state(txt)		do {} while (0)

#define dbg_print_link(...)		do {} while (0)
#define dbg_print_buf_chain(...)	do {} while (0)
#define dbg_print_link_state(...)	do {} while (0)

#endif

/*
 *  Simple link routines
 */

static unsigned int align(unsigned int i)
{
	return (i + 3) & ~3u;
}

static void link_init_max_pkt(struct link *l_ptr)
{
	u32 max_pkt;

	max_pkt = (l_ptr->b_ptr->publ.mtu & ~3);
	if (max_pkt > MAX_MSG_SIZE)
		max_pkt = MAX_MSG_SIZE;

	l_ptr->max_pkt_target = max_pkt;
	if (l_ptr->max_pkt_target < MAX_PKT_DEFAULT)
		l_ptr->max_pkt = l_ptr->max_pkt_target;
	else
		l_ptr->max_pkt = MAX_PKT_DEFAULT;

	l_ptr->max_pkt_probes = 0;
}

static u32 link_next_sent(struct link *l_ptr)
{
	if (l_ptr->next_out)
		return buf_seqno(l_ptr->next_out);
	return mod(l_ptr->next_out_no);
}

static u32 link_last_sent(struct link *l_ptr)
{
	return mod(link_next_sent(l_ptr) - 1);
}

/*
 *  Simple non-static link routines (i.e. referenced outside this file)
 */

int tipc_link_is_up(struct link *l_ptr)
{
	if (!l_ptr)
		return 0;
	return (link_working_working(l_ptr) || link_working_unknown(l_ptr));
}

int tipc_link_is_active(struct link *l_ptr)
{
	return ((l_ptr->owner->active_links[0] == l_ptr) ||
		(l_ptr->owner->active_links[1] == l_ptr));
}

#ifdef CONFIG_TIPC_CONFIG_SERVICE

/**
 * link_name_validate - validate & (optionally) deconstruct link name
 * @name - ptr to link name string
 * @name_parts - ptr to area for link name components (or NULL if not needed)
 *
 * Returns 1 if link name is valid, otherwise 0.
 */

static int link_name_validate(const char *name, struct link_name *name_parts)
{
	char name_copy[TIPC_MAX_LINK_NAME];
	char *addr_local;
	char *if_local;
	char *addr_peer;
	char *if_peer;
	char dummy;
	u32 z_local, c_local, n_local;
	u32 z_peer, c_peer, n_peer;
	u32 if_local_len;
	u32 if_peer_len;

	/* copy link name & ensure length is OK */

	name_copy[TIPC_MAX_LINK_NAME - 1] = 0;
	/* need above in case non-Posix strncpy() doesn't pad with nulls */
	strncpy(name_copy, name, TIPC_MAX_LINK_NAME);
	if (name_copy[TIPC_MAX_LINK_NAME - 1] != 0)
		return 0;

	/* ensure all component parts of link name are present */

	addr_local = name_copy;
	if ((if_local = strchr(addr_local, ':')) == NULL)
		return 0;
	*(if_local++) = 0;
	if ((addr_peer = strchr(if_local, '-')) == NULL)
		return 0;
	*(addr_peer++) = 0;
	if_local_len = addr_peer - if_local;
	if ((if_peer = strchr(addr_peer, ':')) == NULL)
		return 0;
	*(if_peer++) = 0;
	if_peer_len = strlen(if_peer) + 1;

	/* validate component parts of link name */

	if ((sscanf(addr_local, "%u.%u.%u%c",
		    &z_local, &c_local, &n_local, &dummy) != 3) ||
	    (sscanf(addr_peer, "%u.%u.%u%c",
		    &z_peer, &c_peer, &n_peer, &dummy) != 3) ||
	    (z_local > 255) || (c_local > 4095) || (n_local > 4095) ||
	    (z_peer  > 255) || (c_peer  > 4095) || (n_peer  > 4095) ||
	    (if_local_len <= 1) || (if_local_len > TIPC_MAX_IF_NAME) ||
	    (if_peer_len  <= 1) || (if_peer_len  > TIPC_MAX_IF_NAME) ||
	    (strspn(if_local, tipc_alphabet) != (if_local_len - 1)) ||
	    (strspn(if_peer, tipc_alphabet) != (if_peer_len - 1)))
		return 0;

	/* return link name components, if necessary */

	if (name_parts) {
		name_parts->addr_local = tipc_addr(z_local, c_local, n_local);
		strcpy(name_parts->if_local, if_local);
		name_parts->addr_peer = tipc_addr(z_peer, c_peer, n_peer);
		strcpy(name_parts->if_peer, if_peer);
	}
	return 1;
}

#endif

/**
 * link_timeout - handle expiration of link timer
 * @l_ptr: pointer to link
 *
 * This routine must not grab "tipc_net_lock" to avoid a potential deadlock conflict
 * with tipc_link_delete().  (There is no risk that the node will be deleted by
 * another thread because tipc_link_delete() always cancels the link timer before
 * tipc_node_delete() is called.)
 */

static void link_timeout(struct link *l_ptr)
{
	tipc_node_lock(l_ptr->owner);

	/* update counters used in statistical profiling of send traffic */

	l_ptr->stats.accu_queue_sz += l_ptr->out_queue_size;
	l_ptr->stats.queue_sz_counts++;

	if (l_ptr->out_queue_size > l_ptr->stats.max_queue_sz)
		l_ptr->stats.max_queue_sz = l_ptr->out_queue_size;

	if (l_ptr->first_out) {
		struct tipc_msg *msg = buf_msg(l_ptr->first_out);
		u32 length = msg_size(msg);

		if ((msg_user(msg) == MSG_FRAGMENTER)
		    && (msg_type(msg) == FIRST_FRAGMENT)) {
			length = msg_size(msg_get_wrapped(msg));
		}
		if (length) {
			l_ptr->stats.msg_lengths_total += length;
			l_ptr->stats.msg_length_counts++;
			if (length <= 64)
				l_ptr->stats.msg_length_profile[0]++;
			else if (length <= 256)
				l_ptr->stats.msg_length_profile[1]++;
			else if (length <= 1024)
				l_ptr->stats.msg_length_profile[2]++;
			else if (length <= 4096)
				l_ptr->stats.msg_length_profile[3]++;
			else if (length <= 16384)
				l_ptr->stats.msg_length_profile[4]++;
			else if (length <= 32768)
				l_ptr->stats.msg_length_profile[5]++;
			else
				l_ptr->stats.msg_length_profile[6]++;
		}
	}

	/* do all other link processing performed on a periodic basis */

	link_check_defragm_bufs(l_ptr);

	link_state_event(l_ptr, TIMEOUT_EVT);

	if (l_ptr->next_out)
		tipc_link_push_queue(l_ptr);

	tipc_node_unlock(l_ptr->owner);
}

static void link_set_timer(struct link *l_ptr, u32 time)
{
	k_start_timer(&l_ptr->timer, time);
}

/**
 * tipc_link_create - create a new link
 * @b_ptr: pointer to associated bearer
 * @peer: network address of node at other end of link
 * @media_addr: media address to use when sending messages over link
 *
 * Returns pointer to link.
 */

struct link *tipc_link_create(struct bearer *b_ptr, const u32 peer,
			      const struct tipc_media_addr *media_addr)
{
	struct link *l_ptr;
	struct tipc_msg *msg;
	char *if_name;

	l_ptr = kzalloc(sizeof(*l_ptr), GFP_ATOMIC);
	if (!l_ptr) {
		warn("Link creation failed, no memory\n");
		return NULL;
	}

	if (LINK_LOG_BUF_SIZE) {
		char *pb = kmalloc(LINK_LOG_BUF_SIZE, GFP_ATOMIC);

		if (!pb) {
			kfree(l_ptr);
			warn("Link creation failed, no memory for print buffer\n");
			return NULL;
		}
		tipc_printbuf_init(&l_ptr->print_buf, pb, LINK_LOG_BUF_SIZE);
	}

	l_ptr->addr = peer;
	if_name = strchr(b_ptr->publ.name, ':') + 1;
	sprintf(l_ptr->name, "%u.%u.%u:%s-%u.%u.%u:",
		tipc_zone(tipc_own_addr), tipc_cluster(tipc_own_addr),
		tipc_node(tipc_own_addr),
		if_name,
		tipc_zone(peer), tipc_cluster(peer), tipc_node(peer));
		/* note: peer i/f is appended to link name by reset/activate */
	memcpy(&l_ptr->media_addr, media_addr, sizeof(*media_addr));
	l_ptr->checkpoint = 1;
	l_ptr->b_ptr = b_ptr;
	link_set_supervision_props(l_ptr, b_ptr->tolerance);
	l_ptr->state = RESET_UNKNOWN;
	l_ptr->pmsg = (struct tipc_msg *)&l_ptr->proto_msg;
	msg = l_ptr->pmsg;
	tipc_msg_init(msg, LINK_PROTOCOL, RESET_MSG, INT_H_SIZE, l_ptr->addr);
	msg_set_size(msg, sizeof(l_ptr->proto_msg));
	msg_set_session(msg, (tipc_random & 0xffff));
	msg_set_bearer_id(msg, b_ptr->identity);
	strcpy((char *)msg_data(msg), if_name);
	l_ptr->priority = b_ptr->priority;
	tipc_link_set_queue_limits(l_ptr, b_ptr->window);
	link_init_max_pkt(l_ptr);
	l_ptr->next_out_no = 1;
	INIT_LIST_HEAD(&l_ptr->waiting_ports);
	link_reset_statistics(l_ptr);

	l_ptr->owner = tipc_node_attach_link(l_ptr);
	if (!l_ptr->owner) {
		if (LINK_LOG_BUF_SIZE)
			kfree(l_ptr->print_buf.buf);
		kfree(l_ptr);
		return NULL;
	}

	k_init_timer(&l_ptr->timer, (Handler)link_timeout, (unsigned long)l_ptr);
	list_add_tail(&l_ptr->link_list, &b_ptr->links);

	tipc_k_signal((Handler)tipc_link_start, (unsigned long)l_ptr);

	dbg("tipc_link_create(): tolerance = %u,cont intv = %u, abort_limit = %u\n",
	    l_ptr->tolerance, l_ptr->continuity_interval, l_ptr->abort_limit);

	return l_ptr;
}

/**
 * tipc_link_delete - delete a link
 * @l_ptr: pointer to link
 *
 * Note: 'tipc_net_lock' is write_locked, bearer is locked.
 * This routine must not grab the node lock until after link timer cancellation
 * to avoid a potential deadlock situation.
 */

void tipc_link_delete(struct link *l_ptr)
{
	if (!l_ptr) {
		err("Attempt to delete non-existent link\n");
		return;
	}

	k_cancel_timer(&l_ptr->timer);
	tipc_node_lock(l_ptr->owner);
	tipc_link_reset(l_ptr);
	tipc_node_detach_link(l_ptr->owner, l_ptr);
	tipc_link_stop(l_ptr);
	list_del_init(&l_ptr->link_list);
	if (LINK_LOG_BUF_SIZE)
		kfree(l_ptr->print_buf.buf);
	tipc_node_unlock(l_ptr->owner);
	k_term_timer(&l_ptr->timer);
	kfree(l_ptr);
}

/** 
 * link_remote_delete - delete a link on command from other end
 * @l_ptr: pointer to link
 * 
 * Note: The call comes via a tipc_k_signal. No locks are set at this moment.
 */

static void link_remote_delete(struct link *l_ptr)
{
        struct bearer *b_ptr = l_ptr->b_ptr;

	write_lock_bh(&tipc_net_lock);
        spin_lock_bh(&b_ptr->publ.lock);
        tipc_bearer_remove_discoverer(b_ptr,l_ptr->addr);
        tipc_link_delete(l_ptr);
        spin_unlock_bh(&b_ptr->publ.lock);
	write_unlock_bh(&tipc_net_lock);
}

void tipc_link_start(struct link *l_ptr)
{
	dbg("tipc_link_start %x\n", l_ptr);
	link_state_event(l_ptr, STARTING_EVT);
}

/**
 * link_schedule_port - schedule port for deferred sending
 * @l_ptr: pointer to link
 * @origport: reference to sending port
 * @sz: amount of data to be sent
 *
 * Schedules port for renewed sending of messages after link congestion
 * has abated.
 */

static int link_schedule_port(struct link *l_ptr, u32 origport, u32 sz)
{
	struct port *p_ptr;

	spin_lock_bh(&tipc_port_list_lock);
	p_ptr = tipc_port_lock(origport);
	if (p_ptr) {
		if (!p_ptr->wakeup)
			goto exit;
		if (!list_empty(&p_ptr->wait_list))
			goto exit;
		p_ptr->publ.congested = 1;
		p_ptr->waiting_pkts = 1 + ((sz - 1) / l_ptr->max_pkt);
		list_add_tail(&p_ptr->wait_list, &l_ptr->waiting_ports);
		l_ptr->stats.link_congs++;
exit:
		tipc_port_unlock(p_ptr);
	}
	spin_unlock_bh(&tipc_port_list_lock);
	return -ELINKCONG;
}

void tipc_link_wakeup_ports(struct link *l_ptr, int all)
{
	struct port *p_ptr;
	struct port *temp_p_ptr;
	int win = l_ptr->queue_limit[0] - l_ptr->out_queue_size;

	if (all)
		win = 100000;
	if (win <= 0)
		return;
	if (!spin_trylock_bh(&tipc_port_list_lock))
		return;
	if (link_congested(l_ptr))
		goto exit;
	list_for_each_entry_safe(p_ptr, temp_p_ptr, &l_ptr->waiting_ports,
				 wait_list) {
		if (win <= 0)
			break;
		list_del_init(&p_ptr->wait_list);
		spin_lock_bh(p_ptr->publ.lock);
		p_ptr->publ.congested = 0;
		p_ptr->wakeup(&p_ptr->publ);
		win -= p_ptr->waiting_pkts;
		spin_unlock_bh(p_ptr->publ.lock);
	}

exit:
	spin_unlock_bh(&tipc_port_list_lock);
}

/**
 * link_release_outqueue - purge link's outbound message queue
 * @l_ptr: pointer to link
 */

static void link_release_outqueue(struct link *l_ptr)
{
	struct sk_buff *buf = l_ptr->first_out;
	struct sk_buff *next;

	while (buf) {
		next = buf->next;
		buf_discard(buf);
		buf = next;
	}
	l_ptr->first_out = NULL;
	l_ptr->out_queue_size = 0;
}

/**
 * tipc_link_reset_fragments - purge link's inbound message fragments queue
 * @l_ptr: pointer to link
 */

void tipc_link_reset_fragments(struct link *l_ptr)
{
	struct sk_buff *buf = l_ptr->defragm_buf;
	struct sk_buff *next;

	while (buf) {
		next = buf->next;
		buf_discard(buf);
		buf = next;
	}
	l_ptr->defragm_buf = NULL;
}

/**
 * tipc_link_stop - purge all inbound and outbound messages associated with link
 * @l_ptr: pointer to link
 */

void tipc_link_stop(struct link *l_ptr)
{
	struct sk_buff *buf;
	struct sk_buff *next;

	buf = l_ptr->oldest_deferred_in;
	while (buf) {
		next = buf->next;
		buf_discard(buf);
		buf = next;
	}

	buf = l_ptr->first_out;
	while (buf) {
		next = buf->next;
		buf_discard(buf);
		buf = next;
	}

	tipc_link_reset_fragments(l_ptr);

	buf_discard(l_ptr->proto_msg_queue);
	l_ptr->proto_msg_queue = NULL;
}


void tipc_link_reset(struct link *l_ptr)
{
	struct sk_buff *buf;
	u32 prev_state = l_ptr->state;
	u32 checkpoint = l_ptr->next_in_no;
	int was_active_link = tipc_link_is_active(l_ptr);

	msg_set_session(l_ptr->pmsg, ((msg_session(l_ptr->pmsg) + 1) & 0xffff));

	/* Link is down, accept any session */
	l_ptr->peer_session = INVALID_SESSION;

	/* Prepare for max packet size negotiation */
	link_init_max_pkt(l_ptr);

	l_ptr->state = RESET_UNKNOWN;
	dbg_link_state("Resetting Link\n");

	if ((prev_state == RESET_UNKNOWN) || (prev_state == RESET_RESET))
		return;

	tipc_node_link_down(l_ptr->owner, l_ptr);
	tipc_bearer_remove_dest(l_ptr->b_ptr, l_ptr->addr, &l_ptr->media_addr);
#if 0
	printk("\nReset link <%s>\n", l_ptr->name);
	dbg_link_dump("\n\nDumping link <%s>:\n", l_ptr->name);
#endif
	if (was_active_link && tipc_node_is_up(l_ptr->owner) &&
	    l_ptr->owner->permit_changeover) {
		l_ptr->reset_checkpoint = checkpoint;
		l_ptr->exp_msg_count = START_CHANGEOVER;
	}

	/* Clean up all queues: */

	link_release_outqueue(l_ptr);
	buf_discard(l_ptr->proto_msg_queue);
	l_ptr->proto_msg_queue = NULL;
	buf = l_ptr->oldest_deferred_in;
	while (buf) {
		struct sk_buff *next = buf->next;
		buf_discard(buf);
		buf = next;
	}
	if (!list_empty(&l_ptr->waiting_ports))
		tipc_link_wakeup_ports(l_ptr, 1);

	l_ptr->retransm_queue_head = 0;
	l_ptr->retransm_queue_size = 0;
	l_ptr->last_out = NULL;
	l_ptr->first_out = NULL;
	l_ptr->next_out = NULL;
	l_ptr->unacked_window = 0;
	l_ptr->checkpoint = 1;
	l_ptr->next_out_no = 1;
	l_ptr->deferred_inqueue_sz = 0;
	l_ptr->oldest_deferred_in = NULL;
	l_ptr->newest_deferred_in = NULL;
	l_ptr->fsm_msg_cnt = 0;
	l_ptr->stale_count = 0;
	link_reset_statistics(l_ptr);
}


static void link_activate(struct link *l_ptr)
{
	l_ptr->next_in_no = l_ptr->stats.recv_info = 1;
	tipc_node_link_up(l_ptr->owner, l_ptr);
	tipc_bearer_add_dest(l_ptr->b_ptr, l_ptr->addr, &l_ptr->media_addr);
}

/**
 * link_state_event - link finite state machine
 * @l_ptr: pointer to link
 * @event: state machine event to process
 */

static void link_state_event(struct link *l_ptr, unsigned event)
{
	struct link *other;
	u32 cont_intv = l_ptr->continuity_interval;

	if (!l_ptr->started && (event != STARTING_EVT))
		return;		/* Not yet. */

	if (link_blocked(l_ptr)) {
		if (event == TIMEOUT_EVT) {
			link_set_timer(l_ptr, cont_intv);
		}
		return;	  /* Changeover going on */
	}
	dbg_link("STATE_EV: <%s> ", l_ptr->name);

	switch (l_ptr->state) {
	case WORKING_WORKING:
		dbg_link("WW/");
		switch (event) {
		case TRAFFIC_MSG_EVT:
			dbg_link("TRF-");
			/* fall through */
		case ACTIVATE_MSG:
			dbg_link("ACT\n");
			break;
		case TIMEOUT_EVT:
			dbg_link("TIM ");
			if (l_ptr->next_in_no != l_ptr->checkpoint) {
				l_ptr->checkpoint = l_ptr->next_in_no;
				if (tipc_bclink_acks_missing(l_ptr->owner)) {
					tipc_link_send_proto_msg(l_ptr, STATE_MSG,
							    0, 0, 0, 0, 0, 0);
					l_ptr->fsm_msg_cnt++;
				} else if (l_ptr->max_pkt < l_ptr->max_pkt_target) {
					tipc_link_send_proto_msg(l_ptr, STATE_MSG,
							    1, 0, 0, 0, 0, 0);
					l_ptr->fsm_msg_cnt++;
				}
				link_set_timer(l_ptr, cont_intv);
				break;
			}
			dbg_link(" -> WU\n");
			l_ptr->state = WORKING_UNKNOWN;
			l_ptr->fsm_msg_cnt = 0;
			tipc_link_send_proto_msg(l_ptr, STATE_MSG, 1, 0, 0, 0, 0, 0);
			l_ptr->fsm_msg_cnt++;
			link_set_timer(l_ptr, cont_intv / 4);
			break;
		case RESET_MSG:
			dbg_link("RES -> RR\n");
			info("Resetting link <%s>, requested by peer\n",
			     l_ptr->name);
			tipc_link_reset(l_ptr);
			l_ptr->state = RESET_RESET;
			l_ptr->fsm_msg_cnt = 0;
			tipc_link_send_proto_msg(l_ptr, ACTIVATE_MSG, 0, 0, 0, 0, 0, 0);
			l_ptr->fsm_msg_cnt++;
			link_set_timer(l_ptr, cont_intv);
			break;
		default:
			err("Unknown link event %u in WW state\n", event);
		}
		break;
	case WORKING_UNKNOWN:
		dbg_link("WU/");
		switch (event) {
		case TRAFFIC_MSG_EVT:
			dbg_link("TRF-");
		case ACTIVATE_MSG:
			dbg_link("ACT -> WW\n");
			l_ptr->state = WORKING_WORKING;
			l_ptr->fsm_msg_cnt = 0;
			link_set_timer(l_ptr, cont_intv);
			break;
		case RESET_MSG:
			dbg_link("RES -> RR\n");
			info("Resetting link <%s>, requested by peer "
			     "while probing\n", l_ptr->name);
			tipc_link_reset(l_ptr);
			l_ptr->state = RESET_RESET;
			l_ptr->fsm_msg_cnt = 0;
			tipc_link_send_proto_msg(l_ptr, ACTIVATE_MSG, 0, 0, 0, 0, 0, 0);
			l_ptr->fsm_msg_cnt++;
			link_set_timer(l_ptr, cont_intv);
			break;
		case TIMEOUT_EVT:
			dbg_link("TIM ");
			if (l_ptr->next_in_no != l_ptr->checkpoint) {
				dbg_link("-> WW \n");
				l_ptr->state = WORKING_WORKING;
				l_ptr->fsm_msg_cnt = 0;
				l_ptr->checkpoint = l_ptr->next_in_no;
				if (tipc_bclink_acks_missing(l_ptr->owner)) {
					tipc_link_send_proto_msg(l_ptr, STATE_MSG,
							    0, 0, 0, 0, 0, 0);
					l_ptr->fsm_msg_cnt++;
				}
				link_set_timer(l_ptr, cont_intv);
			} else if (l_ptr->fsm_msg_cnt < l_ptr->abort_limit) {
				dbg_link("Probing %u/%u,timer = %u ms)\n",
					 l_ptr->fsm_msg_cnt, l_ptr->abort_limit,
					 cont_intv / 4);
				tipc_link_send_proto_msg(l_ptr, STATE_MSG, 
						    1, 0, 0, 0, 0, 0);
				l_ptr->fsm_msg_cnt++;
				link_set_timer(l_ptr, cont_intv / 4);
			} else {	/* Link has failed */
				dbg_link("-> RU (%u probes unanswered)\n",
					 l_ptr->fsm_msg_cnt);
				warn("Resetting link <%s>, peer not responding\n",
				     l_ptr->name);
				tipc_link_reset(l_ptr);
				l_ptr->state = RESET_UNKNOWN;
				l_ptr->fsm_msg_cnt = 0;
				tipc_link_send_proto_msg(l_ptr, RESET_MSG,
						    0, 0, 0, 0, 0, 0);
				l_ptr->fsm_msg_cnt++;
				link_set_timer(l_ptr, cont_intv);
			}
			break;
		default:
			err("Unknown link event %u in WU state\n", event);
		}
		break;
	case RESET_UNKNOWN:
		dbg_link("RU/");
		switch (event) {
		case TRAFFIC_MSG_EVT:
			dbg_link("TRF-\n");
			break;
		case ACTIVATE_MSG:
			other = l_ptr->owner->active_links[0];
			if (other && link_working_unknown(other)) {
				dbg_link("ACT\n");
				break;
			}
			dbg_link("ACT -> WW\n");
			l_ptr->state = WORKING_WORKING;
			l_ptr->fsm_msg_cnt = 0;
			link_activate(l_ptr);
			tipc_link_send_proto_msg(l_ptr, STATE_MSG, 1, 0, 0, 0, 0, 0);
			l_ptr->fsm_msg_cnt++;
			link_set_timer(l_ptr, cont_intv);
			break;
		case RESET_MSG:
			dbg_link("RES \n");
			dbg_link(" -> RR\n");
			l_ptr->state = RESET_RESET;
			l_ptr->fsm_msg_cnt = 0;
			tipc_link_send_proto_msg(l_ptr, ACTIVATE_MSG, 1, 0, 0, 0, 0, 0);
			l_ptr->fsm_msg_cnt++;
			link_set_timer(l_ptr, cont_intv);
			break;
		case STARTING_EVT:
			dbg_link("START-");
			l_ptr->started = 1;
			/* fall through */
		case TIMEOUT_EVT:
			dbg_link("TIM \n");
                        tipc_bearer_send_discover(l_ptr->b_ptr,l_ptr->addr);
			tipc_link_send_proto_msg(l_ptr, RESET_MSG, 0, 0, 0, 0, 0, 0);
			l_ptr->fsm_msg_cnt++;
			link_set_timer(l_ptr, cont_intv);
			break;
		default:
			err("Unknown link event %u in RU state\n", event);
		}
		break;
	case RESET_RESET:
		dbg_link("RR/ ");
		switch (event) {
		case TRAFFIC_MSG_EVT:
			dbg_link("TRF-");
			/* fall through */
		case ACTIVATE_MSG:
			other = l_ptr->owner->active_links[0];
			if (other && link_working_unknown(other)) {
				dbg_link("ACT\n");
				break;
			}
			dbg_link("ACT -> WW\n");
			l_ptr->state = WORKING_WORKING;
			l_ptr->fsm_msg_cnt = 0;
			link_activate(l_ptr);
			tipc_link_send_proto_msg(l_ptr, STATE_MSG, 1, 0, 0, 0, 0, 0);
			l_ptr->fsm_msg_cnt++;
			link_set_timer(l_ptr, cont_intv);
			break;
		case RESET_MSG:
			dbg_link("RES\n");
			break;
		case TIMEOUT_EVT:
			dbg_link("TIM\n");
			tipc_link_send_proto_msg(l_ptr, ACTIVATE_MSG, 0, 0, 0, 0, 0, 0);
			l_ptr->fsm_msg_cnt++;
			link_set_timer(l_ptr, cont_intv);
			dbg_link("fsm_msg_cnt %u\n", l_ptr->fsm_msg_cnt);
			break;
		default:
			err("Unknown link event %u in RR state\n", event);
		}
		break;
	default:
		err("Unknown link state %u/%u\n", l_ptr->state, event);
	}
}

/*
 * link_bundle_buf(): Append contents of a buffer to
 * the tail of an existing one.
 */

static int link_bundle_buf(struct link *l_ptr,
			   struct sk_buff *bundler,
			   struct sk_buff *buf)
{
	struct tipc_msg *bundler_msg = buf_msg(bundler);
	struct tipc_msg *msg = buf_msg(buf);
	u32 size = msg_size(msg);
	u32 bundle_size = msg_size(bundler_msg);
	u32 to_pos = align(bundle_size);
	u32 pad = to_pos - bundle_size;

	if (msg_user(bundler_msg) != MSG_BUNDLER)
		return 0;
	if (msg_type(bundler_msg) != OPEN_MSG)
		return 0;
	if (skb_tailroom(bundler) < (pad + size))
		return 0;
	if (l_ptr->max_pkt < (to_pos + size))
		return 0;

	skb_put(bundler, pad + size);
	skb_copy_to_linear_data_offset(bundler, to_pos, buf->data, size);
	msg_set_size(bundler_msg, to_pos + size);
	msg_set_msgcnt(bundler_msg, msg_msgcnt(bundler_msg) + 1);
	dbg("Packed msg # %u(%u octets) into pos %u in buf(#%u)\n",
	    msg_msgcnt(bundler_msg), size, to_pos, msg_seqno(bundler_msg));
	msg_dbg(msg, "PACKD:");
	buf_discard(buf);
	l_ptr->stats.sent_bundled++;
	return 1;
}

static void link_add_to_outqueue(struct link *l_ptr,
				 struct sk_buff *buf,
				 struct tipc_msg *msg)
{
	u32 ack = mod(l_ptr->next_in_no - 1);
	u32 seqno = mod(l_ptr->next_out_no++);

	msg_set_word(msg, 2, ((ack << 16) | seqno));
	msg_set_bcast_ack(msg, l_ptr->owner->bclink.last_in);
	buf->next = NULL;
	if (l_ptr->first_out) {
		l_ptr->last_out->next = buf;
		l_ptr->last_out = buf;
	} else
		l_ptr->first_out = l_ptr->last_out = buf;
	l_ptr->out_queue_size++;
}

/*
 * tipc_link_send_buf() is the 'full path' for messages, called from
 * inside TIPC when the 'fast path' in tipc_send_buf
 * has failed, and from link_send()
 */

int tipc_link_send_buf(struct link *l_ptr, struct sk_buff *buf)
{
	struct tipc_msg *msg = buf_msg(buf);
	u32 size = msg_size(msg);
	u32 dsz = msg_data_sz(msg);
	u32 queue_size = l_ptr->out_queue_size;
	u32 imp = tipc_msg_tot_importance(msg);
	u32 queue_limit = l_ptr->queue_limit[imp];
	u32 max_packet = l_ptr->max_pkt;

	msg_set_prevnode(msg, tipc_own_addr);	/* If routed message */

	/* Match msg importance against queue limits: */

	if (unlikely(queue_size >= queue_limit)) {
		if (imp <= TIPC_CRITICAL_IMPORTANCE) {
			return link_schedule_port(l_ptr, msg_origport(msg),
						  size);
		}
		msg_dbg(msg, "TIPC: Congestion, throwing away\n");
		buf_discard(buf);
		if (imp > CONN_MANAGER) {
			warn("Resetting link <%s>, send queue full", l_ptr->name);
			tipc_link_reset(l_ptr);
		}
		return dsz;
	}

	/* Fragmentation needed ? */

	if (size > max_packet)
		return tipc_link_send_long_buf(l_ptr, buf);

	/* Packet can be queued or sent: */

	if (queue_size > l_ptr->stats.max_queue_sz)
		l_ptr->stats.max_queue_sz = queue_size;

	if (likely(!tipc_bearer_congested(l_ptr->b_ptr, l_ptr) &&
		   !link_congested(l_ptr))) {
		link_add_to_outqueue(l_ptr, buf, msg);

		if (likely(tipc_bearer_send(l_ptr->b_ptr, buf, &l_ptr->media_addr))) {
			l_ptr->unacked_window = 0;
		} else {
			tipc_bearer_schedule(l_ptr->b_ptr, l_ptr);
			l_ptr->stats.bearer_congs++;
			l_ptr->next_out = buf;
		}
		return dsz;
	}
	/* Congestion: can message be bundled ?: */

	if ((msg_user(msg) != CHANGEOVER_PROTOCOL) &&
	    (msg_user(msg) != MSG_FRAGMENTER)) {

		/* Try adding message to an existing bundle */

		if (l_ptr->next_out &&
		    link_bundle_buf(l_ptr, l_ptr->last_out, buf)) {
			tipc_bearer_resolve_congestion(l_ptr->b_ptr, l_ptr);
			return dsz;
		}

		/* Try creating a new bundle */

		if (size <= max_packet * 2 / 3) {
			struct sk_buff *bundler = buf_acquire(max_packet);
			struct tipc_msg bundler_hdr;

			if (bundler) {
				tipc_msg_init(&bundler_hdr, MSG_BUNDLER, OPEN_MSG,
					      INT_H_SIZE, l_ptr->addr);
				skb_copy_to_linear_data(bundler, &bundler_hdr,
							INT_H_SIZE);
				skb_trim(bundler, INT_H_SIZE);
				link_bundle_buf(l_ptr, bundler, buf);
				buf = bundler;
				msg = buf_msg(buf);
				l_ptr->stats.sent_bundles++;
			}
		}
	}
	if (!l_ptr->next_out)
		l_ptr->next_out = buf;
	link_add_to_outqueue(l_ptr, buf, msg);
	tipc_bearer_resolve_congestion(l_ptr->b_ptr, l_ptr);
	return dsz;
}

/*
 * tipc_link_send(): same as tipc_link_send_buf(), but the link to use has
 * not been selected yet, and the the owner node is not locked
 * Called by TIPC internal users, e.g. the name distributor
 */

int tipc_link_send(struct sk_buff *buf, u32 dest, u32 selector)
{
	struct link *l_ptr;
	struct tipc_node *n_ptr;
	int res = -ELINKCONG;

	read_lock_bh(&tipc_net_lock);
	n_ptr = tipc_net_select_node(dest);
	if (n_ptr) {
		tipc_node_lock(n_ptr);
		l_ptr = n_ptr->active_links[selector & 1];
		if (l_ptr) {
			dbg("tipc_link_send: found link %x for dest %x\n", l_ptr, dest);
			res = tipc_link_send_buf(l_ptr, buf);
		} else {
			dbg("Attempt to send msg to unreachable node:\n");
			msg_dbg(buf_msg(buf),">>>");
			buf_discard(buf);
		}
		tipc_node_unlock(n_ptr);
	} else {
		dbg("Attempt to send msg to unknown node:\n");
		msg_dbg(buf_msg(buf),">>>");
		buf_discard(buf);
	}
	read_unlock_bh(&tipc_net_lock);
	return res;
}

/*
 * link_send_buf_fast: Entry for data messages where the
 * destination link is known and the header is complete,
 * inclusive total message length. Very time critical.
 * Link is locked. Returns user data length.
 */

static int link_send_buf_fast(struct link *l_ptr, struct sk_buff *buf,
			      u32 *used_max_pkt)
{
	struct tipc_msg *msg = buf_msg(buf);
	int res = msg_data_sz(msg);

	if (likely(!link_congested(l_ptr))) {
		if (likely(msg_size(msg) <= l_ptr->max_pkt)) {
			if (likely(list_empty(&l_ptr->b_ptr->cong_links))) {
				link_add_to_outqueue(l_ptr, buf, msg);
				if (likely(tipc_bearer_send(l_ptr->b_ptr, buf,
							    &l_ptr->media_addr))) {
					l_ptr->unacked_window = 0;
					msg_dbg(msg,"SENT_FAST:");
					return res;
				}
				dbg("failed sent fast...\n");
				tipc_bearer_schedule(l_ptr->b_ptr, l_ptr);
				l_ptr->stats.bearer_congs++;
				l_ptr->next_out = buf;
				return res;
			}
		}
		else
			*used_max_pkt = l_ptr->max_pkt;
	}
	return tipc_link_send_buf(l_ptr, buf);  /* All other cases */
}

/*
 * tipc_send_buf_fast: Entry for data messages where the
 * destination node is known to be off-node and the header is complete,
 * inclusive total message length.
 * Returns user data length.
 */
int tipc_send_buf_fast(struct sk_buff *buf, u32 destnode)
{
	struct link *l_ptr;
	struct tipc_node *n_ptr;
	int res;
	u32 selector = msg_origport(buf_msg(buf)) & 1;
	u32 dummy;

	assert(!addr_in_node(destnode));

	read_lock_bh(&tipc_net_lock);
	n_ptr = tipc_net_select_node(destnode);

	if (likely(n_ptr)) {
		tipc_node_lock(n_ptr);
		l_ptr = n_ptr->active_links[selector];
		dbg("send_fast: buf %x selected %x, destnode = %x\n",
		    buf, l_ptr, destnode);
		if (likely(l_ptr)) {
			res = link_send_buf_fast(l_ptr, buf, &dummy);
			tipc_node_unlock(n_ptr);
			read_unlock_bh(&tipc_net_lock);
			return res;
		}
		tipc_node_unlock(n_ptr);
	}
	read_unlock_bh(&tipc_net_lock);
	res = msg_data_sz(buf_msg(buf));
	tipc_reject_msg(buf, TIPC_ERR_NO_NODE);
	return res;
}


/*
 * tipc_link_send_sections_fast: Entry for messages where the
 * destination processor is known and the header is complete,
 * except for total message length.
 * Returns user data length or errno.
 */
int tipc_link_send_sections_fast(struct port *sender,
				 struct iovec const *msg_sect,
				 const u32 num_sect,
				 u32 destaddr)
{
	struct tipc_msg *hdr = &sender->publ.phdr;
	struct link *l_ptr;
	struct sk_buff *buf;
	struct tipc_node *node;
	int res;
	u32 selector = msg_origport(hdr) & 1;

again:
	/*
	 * Try building message using port's max_pkt hint.
	 * (Must not hold any locks while building message.)
	 */

	res = tipc_msg_build(hdr, msg_sect, num_sect, sender->publ.max_pkt,
			     !sender->user_port, &buf);

	read_lock_bh(&tipc_net_lock);
	node = tipc_net_select_node(destaddr);

	if (likely(node)) {
		tipc_node_lock(node);
		l_ptr = node->active_links[selector];
		if (likely(l_ptr)) {
			if (likely(buf)) {
				res = link_send_buf_fast(l_ptr, buf,
							 &sender->publ.max_pkt);
				if (unlikely(res < 0))
					buf_discard(buf);
exit:
				tipc_node_unlock(node);
				read_unlock_bh(&tipc_net_lock);
				return res;
			}

			/* Exit if build request was invalid */

			if (unlikely(res < 0))
				goto exit;

			/* Exit if link (or bearer) is congested */

			if (link_congested(l_ptr) || 
			    !list_empty(&l_ptr->b_ptr->cong_links)) {
				res = link_schedule_port(l_ptr,
							 sender->publ.ref, res);
				goto exit;
			}

			/* 
			 * Message size exceeds max_pkt hint; update hint,
			 * then re-try fast path or fragment the message
			 */

			sender->publ.max_pkt = l_ptr->max_pkt;
			tipc_node_unlock(node);
			read_unlock_bh(&tipc_net_lock);


			if ((msg_hdr_sz(hdr) + res) <= sender->publ.max_pkt)
				goto again;

			return link_send_sections_long(sender, msg_sect,
						       num_sect, destaddr);
		}
		tipc_node_unlock(node);
	}
	read_unlock_bh(&tipc_net_lock);

	/* Couldn't find a link to the destination node */

	if (buf)
		return tipc_reject_msg(buf, TIPC_ERR_NO_NODE);
	if (res >= 0)
		return tipc_port_reject_sections(sender, hdr, msg_sect, num_sect,
						 TIPC_ERR_NO_NODE);
	return res;
}

/*
 * link_send_sections_long(): Entry for long messages where the
 * destination node is known and the header is complete,
 * inclusive total message length.
 * Link and bearer congestion status have been checked to be ok,
 * and are ignored if they change.
 *
 * Note that fragments do not use the full link MTU so that they won't have
 * to undergo refragmentation if link changeover causes them to be sent
 * over another link with an additional tunnel header added as prefix.
 * (Refragmentation will still occur if the other link has a smaller MTU.)
 *
 * Returns user data length or errno.
 */
static int link_send_sections_long(struct port *sender,
				   struct iovec const *msg_sect,
				   u32 num_sect,
				   u32 destaddr)
{
	struct link *l_ptr;
	struct tipc_node *node;
	struct tipc_msg *hdr = &sender->publ.phdr;
	u32 dsz = msg_data_sz(hdr);
	u32 max_pkt,fragm_sz,rest;
	struct tipc_msg fragm_hdr;
	struct sk_buff *buf,*buf_chain,*prev;
	u32 fragm_crs,fragm_rest,hsz,sect_rest;
	const unchar *sect_crs;
	int curr_sect;
	u32 fragm_no;

again:
	fragm_no = 1;
	max_pkt = sender->publ.max_pkt - INT_H_SIZE;
		/* leave room for tunnel header in case of link changeover */
	fragm_sz = max_pkt - INT_H_SIZE;
		/* leave room for fragmentation header in each fragment */
	rest = dsz;
	fragm_crs = 0;
	fragm_rest = 0;
	sect_rest = 0;
	sect_crs = NULL;
	curr_sect = -1;

	/* Prepare reusable fragment header: */

	msg_dbg(hdr, ">FRAGMENTING>");
	tipc_msg_init(&fragm_hdr, MSG_FRAGMENTER, FIRST_FRAGMENT,
		      INT_H_SIZE, msg_destnode(hdr));
	msg_set_link_selector(&fragm_hdr, (sender->publ.ref & 1));
	msg_set_fragm_msg_no(&fragm_hdr, 
			     atomic_inc_return(&link_fragm_msg_no) & 0xffff);
	msg_set_fragm_no(&fragm_hdr, 1);

	/* Prepare header of first fragment: */

	msg_set_size(&fragm_hdr, max_pkt);
	buf_chain = buf = buf_acquire(max_pkt);
	if (!buf)
		return -ENOMEM;
	buf->next = NULL;
	skb_copy_to_linear_data(buf, &fragm_hdr, INT_H_SIZE);
	hsz = msg_hdr_sz(hdr);
	skb_copy_to_linear_data_offset(buf, INT_H_SIZE, hdr, hsz);
	msg_dbg(buf_msg(buf), ">BUILD>");

	/* Chop up message: */

	fragm_crs = INT_H_SIZE + hsz;
	fragm_rest = fragm_sz - hsz;

	do {		/* For all sections */
		u32 sz;

		if (!sect_rest) {
			sect_rest = msg_sect[++curr_sect].iov_len;
			sect_crs = (const unchar *)msg_sect[curr_sect].iov_base;
		}

		if (sect_rest < fragm_rest)
			sz = sect_rest;
		else
			sz = fragm_rest;

		if (likely(!sender->user_port)) {
			if (copy_from_user(buf->data + fragm_crs, sect_crs, sz)) {
error:
				for (; buf_chain; buf_chain = buf) {
					buf = buf_chain->next;
					buf_discard(buf_chain);
				}
				return -EFAULT;
			}
		} else
			skb_copy_to_linear_data_offset(buf, fragm_crs,
						       sect_crs, sz);
		sect_crs += sz;
		sect_rest -= sz;
		fragm_crs += sz;
		fragm_rest -= sz;
		rest -= sz;

		if (!fragm_rest && rest) {

			/* Initiate new fragment: */
			if (rest <= fragm_sz) {
				fragm_sz = rest;
				msg_set_type(&fragm_hdr,LAST_FRAGMENT);
			} else {
				msg_set_type(&fragm_hdr, FRAGMENT);
			}
			msg_set_size(&fragm_hdr, fragm_sz + INT_H_SIZE);
			msg_set_fragm_no(&fragm_hdr, ++fragm_no);
			prev = buf;
			buf = buf_acquire(fragm_sz + INT_H_SIZE);
			if (!buf)
				goto error;

			buf->next = NULL;
			prev->next = buf;
			skb_copy_to_linear_data(buf, &fragm_hdr, INT_H_SIZE);
			fragm_crs = INT_H_SIZE;
			fragm_rest = fragm_sz;
			msg_dbg(buf_msg(buf),"  >BUILD>");
		}
	}
	while (rest > 0);

	/*
	 * Now we have a buffer chain. Select a link and check
	 * that packet size is still OK
	 */

	node = tipc_net_select_node(destaddr);

	if (likely(node)) {
		tipc_node_lock(node);
		l_ptr = node->active_links[sender->publ.ref & 1];
		if (!l_ptr) {
			tipc_node_unlock(node);
			goto reject;
		}
		if (l_ptr->max_pkt < max_pkt) {
			sender->publ.max_pkt = l_ptr->max_pkt;
			tipc_node_unlock(node);
			for (; buf_chain; buf_chain = buf) {
				buf = buf_chain->next;
				buf_discard(buf_chain);
			}
			goto again;
		}
	} else {
reject:
		for (; buf_chain; buf_chain = buf) {
			buf = buf_chain->next;
			buf_discard(buf_chain);
		}
		return tipc_port_reject_sections(sender, hdr, msg_sect, num_sect,
						 TIPC_ERR_NO_NODE);
	}

	/* Append whole chain to send queue: */

	buf = buf_chain;
	if (!l_ptr->next_out)
		l_ptr->next_out = buf_chain;
	l_ptr->stats.sent_fragmented++;
	while (buf) {
		struct sk_buff *next = buf->next;
		struct tipc_msg *msg = buf_msg(buf);

		l_ptr->stats.sent_fragments++;
		link_add_to_outqueue(l_ptr, buf, msg);
		msg_dbg(msg, ">ADD>");
		buf = next;
	}

	/* Send it, if possible: */

	tipc_link_push_queue(l_ptr);
	tipc_node_unlock(node);
	return dsz;
}

/*
 * tipc_link_push_packet: Push one unsent packet to the media
 */
u32 tipc_link_push_packet(struct link *l_ptr)
{
	struct sk_buff *buf = l_ptr->first_out;
	u32 r_q_size = l_ptr->retransm_queue_size;
	u32 r_q_head = l_ptr->retransm_queue_head;

	/* Step to position where retransmission failed, if any,    */
	/* consider that buffers may have been released in meantime */

	if (r_q_size && buf) {
		u32 last = lesser(mod(r_q_head + r_q_size),
				  link_last_sent(l_ptr));
		u32 first = buf_seqno(buf);

		while (buf && less(first, r_q_head)) {
			first = mod(first + 1);
			buf = buf->next;
		}
		l_ptr->retransm_queue_head = r_q_head = first;
		l_ptr->retransm_queue_size = r_q_size = mod(last - first);
	}

	/* Continue retransmission now, if there is anything: */

	if (r_q_size && buf) {
		msg_set_ack(buf_msg(buf), mod(l_ptr->next_in_no - 1));
		msg_set_bcast_ack(buf_msg(buf), l_ptr->owner->bclink.last_in);
		if (tipc_bearer_send(l_ptr->b_ptr, buf, &l_ptr->media_addr)) {
			msg_dbg(buf_msg(buf), ">DEF-RETR>");
			l_ptr->retransm_queue_head = mod(++r_q_head);
			l_ptr->retransm_queue_size = --r_q_size;
			l_ptr->stats.retransmitted++;
			return 0;
		} else {
			l_ptr->stats.bearer_congs++;
			msg_dbg(buf_msg(buf), "|>DEF-RETR>");
			return PUSH_FAILED;
		}
	}

	/* Send deferred protocol message, if any: */

	buf = l_ptr->proto_msg_queue;
	if (buf) {
		msg_set_ack(buf_msg(buf), mod(l_ptr->next_in_no - 1));
		msg_set_bcast_ack(buf_msg(buf),l_ptr->owner->bclink.last_in);
		if (tipc_bearer_send(l_ptr->b_ptr, buf, &l_ptr->media_addr)) {
			msg_dbg(buf_msg(buf), ">DEF-PROT>");
			l_ptr->unacked_window = 0;
			buf_discard(buf);
			l_ptr->proto_msg_queue = NULL;
			return 0;
		} else {
			msg_dbg(buf_msg(buf), "|>DEF-PROT>");
			l_ptr->stats.bearer_congs++;
			return PUSH_FAILED;
		}
	}

	/* Send one deferred data message, if send window not full: */

	buf = l_ptr->next_out;
	if (buf) {
		struct tipc_msg *msg = buf_msg(buf);
		u32 next = msg_seqno(msg);
		u32 first = buf_seqno(l_ptr->first_out);

		if (mod(next - first) < l_ptr->queue_limit[0]) {
			msg_set_ack(msg, mod(l_ptr->next_in_no - 1));
			msg_set_bcast_ack(msg, l_ptr->owner->bclink.last_in);
			if (tipc_bearer_send(l_ptr->b_ptr, buf, &l_ptr->media_addr)) {
				if (msg_user(msg) == MSG_BUNDLER)
					msg_set_type(msg, CLOSED_MSG);
				msg_dbg(msg, ">PUSH-DATA>");
				l_ptr->next_out = buf->next;
				return 0;
			} else {
				msg_dbg(msg, "|PUSH-DATA|");
				l_ptr->stats.bearer_congs++;
				return PUSH_FAILED;
			}
		}
	}
	return PUSH_FINISHED;
}

/*
 * push_queue(): push out the unsent messages of a link where
 *               congestion has abated. Node is locked
 */
void tipc_link_push_queue(struct link *l_ptr)
{
	u32 res;

	if (tipc_bearer_congested(l_ptr->b_ptr, l_ptr))
		return;

	do {
		res = tipc_link_push_packet(l_ptr);
	}
	while (!res);
	if (res == PUSH_FAILED)
		tipc_bearer_schedule(l_ptr->b_ptr, l_ptr);
}

static void link_reset_all(unsigned long addr)
{
	struct tipc_node *n_ptr;
	char addr_string[16];
	u32 i;

	read_lock_bh(&tipc_net_lock);
	n_ptr = tipc_net_find_node((u32)addr);
	if (!n_ptr) {
		read_unlock_bh(&tipc_net_lock);
		return;	/* node no longer exists */
	}

	tipc_node_lock(n_ptr);

	tipc_addr_string_fill(addr_string, addr);
	warn("Resetting all links to %s\n", addr_string);

	for (i = 0; i < TIPC_MAX_BEARERS; i++) {
		if (n_ptr->links[i]) {
			warn("Resetting link <%s>\n", n_ptr->links[i]->name);
			dbg_print_link_state(TIPC_OUTPUT, n_ptr->links[i]);
			tipc_link_reset(n_ptr->links[i]);
		}
	}

	tipc_node_unlock(n_ptr);
	read_unlock_bh(&tipc_net_lock);
}

static void link_retransmit_failure(struct link *l_ptr, struct sk_buff *buf)
{
	warn("Retransmission failure on link <%s>\n", l_ptr->name);
	tipc_msg_dbg(TIPC_OUTPUT, buf_msg(buf), ">RETR-FAIL>");

	if (l_ptr->addr) {

		/* Handle failure on standard link */

		warn("Resetting link <%s>\n", l_ptr->name);
		dbg_print_link_state(TIPC_OUTPUT, l_ptr);
		tipc_link_reset(l_ptr);

	} else {

		/* Handle failure on broadcast link */

		struct tipc_node *n_ptr;
		char addr_string[16];

		dbg_printf(TIPC_OUTPUT, "Msg seq number: %u,  ", buf_seqno(buf));
		dbg_printf(TIPC_OUTPUT, "Outstanding acks: %u\n", (u32)buf_handle(buf));
		
		/* recover retransmit requester */
		n_ptr = (struct tipc_node *)l_ptr->owner->node_list.next;
		tipc_node_lock(n_ptr);

		tipc_addr_string_fill(addr_string, n_ptr->elm.addr);
		dbg_printf(TIPC_OUTPUT, "Broadcast link info for %s\n", addr_string);
		dbg_printf(TIPC_OUTPUT, "Supported: %d,  ", n_ptr->bclink.supported);
		dbg_printf(TIPC_OUTPUT, "Acked: %u\n", n_ptr->bclink.acked);
		dbg_printf(TIPC_OUTPUT, "Last in: %u,  ", n_ptr->bclink.last_in);
		dbg_printf(TIPC_OUTPUT, "Oos state: %u,  ", n_ptr->bclink.oos_state);
		dbg_printf(TIPC_OUTPUT, "Last sent: %u\n", n_ptr->bclink.last_sent);

		tipc_k_signal((Handler)link_reset_all, (unsigned long)n_ptr->elm.addr);

		tipc_node_unlock(n_ptr);

		l_ptr->stale_count = 0;
	}
}

void tipc_link_retransmit(struct link *l_ptr, struct sk_buff *buf,
			  u32 retransmits)
{
	struct tipc_msg *msg;

	if (!buf)
		return;

	msg = buf_msg(buf);

	dbg("Retransmitting %u in link %x\n", retransmits, l_ptr);

	if (tipc_bearer_congested(l_ptr->b_ptr, l_ptr)) {
		if (l_ptr->retransm_queue_size == 0) {
			msg_dbg(msg, ">NO_RETR->BCONG>");
			dbg_print_link(l_ptr, "   ");
			l_ptr->retransm_queue_head = msg_seqno(msg);
			l_ptr->retransm_queue_size = retransmits;
		} else {
			err("Unexpected retransmit on link %s (qsize=%d)\n",
			    l_ptr->name, l_ptr->retransm_queue_size);
		}
		return;
	} else {
		/* Detect repeated retransmit failures on uncongested bearer */

		if (l_ptr->last_retransmitted == msg_seqno(msg)) {
			if (++l_ptr->stale_count > 100) {
				link_retransmit_failure(l_ptr, buf);
				return;
			}
		} else {
			l_ptr->last_retransmitted = msg_seqno(msg);
			l_ptr->stale_count = 1;
		}
	}

	while (retransmits && (buf != l_ptr->next_out) && buf) {
		msg = buf_msg(buf);
		msg_set_ack(msg, mod(l_ptr->next_in_no - 1));
		msg_set_bcast_ack(msg, l_ptr->owner->bclink.last_in);
		if (tipc_bearer_send(l_ptr->b_ptr, buf, &l_ptr->media_addr)) {
			msg_dbg(buf_msg(buf), ">RETR>");
			buf = buf->next;
			retransmits--;
			l_ptr->stats.retransmitted++;
		} else {
			tipc_bearer_schedule(l_ptr->b_ptr, l_ptr);
			l_ptr->stats.bearer_congs++;
			l_ptr->retransm_queue_head = buf_seqno(buf);
			l_ptr->retransm_queue_size = retransmits;
			return;
		}
	}

	l_ptr->retransm_queue_head = l_ptr->retransm_queue_size = 0;
}

/**
 * link_insert_deferred_queue - insert deferred messages back into receive chain
 */

static struct sk_buff *link_insert_deferred_queue(struct link *l_ptr,
						  struct sk_buff *buf)
{
	u32 seq_no;

	if (l_ptr->oldest_deferred_in == NULL)
		return buf;

	seq_no = buf_seqno(l_ptr->oldest_deferred_in);
	if (seq_no == mod(l_ptr->next_in_no)) {
		l_ptr->newest_deferred_in->next = buf;
		buf = l_ptr->oldest_deferred_in;
		l_ptr->oldest_deferred_in = NULL;
		l_ptr->deferred_inqueue_sz = 0;
	}
	return buf;
}

/**
 * link_recv_buf_validate - validate basic format of received message
 *
 * This routine ensures a TIPC message has an acceptable header, and at least
 * as much data as the header indicates it should.  The routine also ensures
 * that the entire message header is stored in the main fragment of the message
 * buffer, to simplify future access to message header fields.
 *
 * Note: Having extra info present in the message header or data areas is OK.
 * TIPC will ignore the excess, under the assumption that it is optional info
 * introduced by a later release of the protocol.
 */

static int link_recv_buf_validate(struct sk_buff *buf)
{
	static u32 min_data_hdr_size[8] = {
		SHORT_H_SIZE, MCAST_H_SIZE, LONG_H_SIZE, DIR_MSG_H_SIZE,
		MAX_H_SIZE, MAX_H_SIZE, MAX_H_SIZE, MAX_H_SIZE
		};

	struct tipc_msg *msg;
	u32 tipc_hdr[2];
	u32 size;
	u32 hdr_size;
	u32 min_hdr_size;

	if (unlikely(buf->len < MIN_H_SIZE))
		return 0;

	msg = skb_header_pointer(buf, 0, sizeof(tipc_hdr), tipc_hdr);
	if (msg == NULL)
		return 0;

	if (unlikely(msg_version(msg) != TIPC_VERSION))
		return 0;

	size = msg_size(msg);
	hdr_size = msg_hdr_sz(msg);
	min_hdr_size = msg_isdata(msg) ?
		min_data_hdr_size[msg_type(msg)] : INT_H_SIZE;

	if (unlikely((hdr_size < min_hdr_size) ||
		     (size < hdr_size) ||
		     (buf->len < size) ||
		     (size - hdr_size > TIPC_MAX_USER_MSG_SIZE)))
		return 0;

	return pskb_may_pull(buf, hdr_size);
}

/**
 * tipc_recv_msg - process TIPC messages arriving from off-node
 * @head: pointer to message buffer chain
 * @tb_ptr: pointer to bearer message arrived on
 * 
 * Invoked with no locks held.  Bearer pointer must point to a valid bearer
 * structure (i.e. cannot be NULL), but bearer can be inactive.
 */

void tipc_recv_msg(struct sk_buff *head, struct tipc_bearer *tb_ptr)
{
	read_lock_bh(&tipc_net_lock);
	while (head) {
		struct bearer *b_ptr = (struct bearer *)tb_ptr;
		struct tipc_node *n_ptr;
		struct link *l_ptr;
		struct sk_buff *crs;
		struct sk_buff *buf;
		struct tipc_msg *msg;
		u32 type;
		u32 seq_no;
		u32 ackd;
		u32 released;

		buf = head;
		head = head->next;

		/* Ensure bearer is still enabled */

		if (unlikely(!b_ptr->active))
			goto cont;
       		
		/* Ensure message is well-formed */

		if (unlikely(!link_recv_buf_validate(buf)))
			goto cont;

		/* 
		 * Ensure message is stored as a single contiguous unit;
		 * support for non-linear sk_buffs is under development ...
		 */

		if (unlikely(buf_linearize(buf))) {
			goto cont;
		}

		/* Handle arrival of a non-unicast link message */

		msg = buf_msg(buf);

		if (unlikely(msg_non_seq(msg))) {
			if (msg_user(msg) == LINK_CONFIG)
				tipc_disc_recv_msg(buf, b_ptr);
			else
				tipc_bclink_recv_pkt(buf);
			continue;
		}

		/* Discard non-routeable messages destined for another node */

		if (unlikely(!msg_isdata(msg) && 
			     (msg_destnode(msg) != tipc_own_addr))) {
			if ((msg_user(msg) != CONN_MANAGER) &&
			    (msg_user(msg) != MSG_FRAGMENTER))
				goto cont;
		}

		/* Locate neighboring node that sent message */

		n_ptr = tipc_net_find_node(msg_prevnode(msg));
		if (unlikely(!n_ptr))
			goto cont;
		tipc_node_lock(n_ptr);

		/* Don't talk to neighbor during cleanup after last session */

		if (n_ptr->cleanup_required) {
			tipc_node_unlock(n_ptr);                
			goto cont;
		}

		/* Locate unicast link endpoint that should handle message */

		l_ptr = n_ptr->links[b_ptr->identity];
		if (unlikely(!l_ptr)) {
			tipc_node_unlock(n_ptr);
			goto cont;
		}

		/* Validate message sequence number info */

		seq_no = msg_seqno(msg);
		ackd = msg_ack(msg);

		/* TODO: Implement stronger sequence # checking someday ... */

		/* Release acked messages */

		if (less(n_ptr->bclink.acked, msg_bcast_ack(msg)) &&
		    tipc_node_is_up(n_ptr) && n_ptr->bclink.supported) {
			tipc_bclink_acknowledge(n_ptr, msg_bcast_ack(msg));
		}

		released = 0;
		crs = l_ptr->first_out;
		while ((crs != l_ptr->next_out) &&
		       less_eq(buf_seqno(crs), ackd)) {
			struct sk_buff *next = crs->next;

			buf_discard(crs);
			crs = next;
			released++;
		}
		if (released) {
			l_ptr->first_out = crs;
			l_ptr->out_queue_size -= released;
		}

		/* Try sending any messages link endpoint has pending */

		if (unlikely(l_ptr->next_out))
			tipc_link_push_queue(l_ptr);
		if (unlikely(!list_empty(&l_ptr->waiting_ports)))
			tipc_link_wakeup_ports(l_ptr, 0);
		if (unlikely(++l_ptr->unacked_window >= TIPC_MIN_LINK_WIN)) {
			l_ptr->stats.sent_acks++;
			tipc_link_send_proto_msg(l_ptr, STATE_MSG, 0, 0, 0, 0, 0, 0);
		}

		/* Now (finally!) process the incoming message */

#ifdef CONFIG_TIPC_MULTIPLE_LINKS
protocol_check:
#endif
		if (likely(link_working_working(l_ptr))) {
			if (likely(seq_no == mod(l_ptr->next_in_no))) {
				l_ptr->next_in_no++;
				if (unlikely(l_ptr->oldest_deferred_in))
					head = link_insert_deferred_queue(l_ptr,
									  head);
deliver:
                                if (likely(msg_isdata(msg))) {
                                        tipc_node_unlock(n_ptr);
                                        if (likely(msg_short(msg) ||
						   (msg_destnode(msg) == tipc_own_addr))) 
                                                tipc_port_recv_msg(buf);
                                        else
                                                tipc_net_route_msg(buf);
                                        continue;
                                } 

				if (unlikely(msg_destnode(msg) != tipc_own_addr)) {
                                        tipc_node_unlock(n_ptr);
					if ((msg_user(msg) != MSG_FRAGMENTER) &&
					    (msg_user(msg) != CONN_MANAGER))
						goto cont;
					tipc_net_route_msg(buf);
					continue;
				}

                                switch (msg_user(msg)) {
                                case MSG_BUNDLER:
                                        l_ptr->stats.recv_bundles++;
                                        l_ptr->stats.recv_bundled += 
                                                msg_msgcnt(msg);
                                        tipc_node_unlock(n_ptr);
                                        tipc_link_recv_bundle(buf);
                                        continue;
				case NAME_DISTRIBUTOR:
                                        tipc_node_unlock(n_ptr);
					tipc_named_recv(buf);
                                        continue;
				case ROUTE_DISTRIBUTOR:
                                        tipc_node_unlock(n_ptr);
					tipc_route_recv(buf);
                                        continue;
                                case CONN_MANAGER:
                                        /* route message normally */
                                        break;
                                case MSG_FRAGMENTER:
                                        l_ptr->stats.recv_fragments++;
                                        if (tipc_link_recv_fragment(&l_ptr->defragm_buf, 
                                                                    &buf, &msg)) {
                                                l_ptr->stats.recv_fragmented++;
                                                goto deliver;
                                        }
                                        break;
#ifdef CONFIG_TIPC_MULTIPLE_LINKS
                                case CHANGEOVER_PROTOCOL:
                                        type = msg_type(msg);
                                        if (link_recv_changeover_msg(&l_ptr, &buf)) {
                                                msg = buf_msg(buf);
                                                seq_no = msg_seqno(msg);
                                                if (type == ORIGINAL_MSG)
                                                        goto deliver;
                                                goto protocol_check;
                                        }
                                        break;
#endif
				default:
					dbg("Unsupported message discarded (user=%d)\n",
					    msg_user(msg));
					buf_discard(buf);
					buf = NULL;
					break;
                                }
				tipc_node_unlock(n_ptr);
				tipc_net_route_msg(buf);
				continue;
			}
			link_handle_out_of_seq_msg(l_ptr, buf);
			head = link_insert_deferred_queue(l_ptr, head);
			tipc_node_unlock(n_ptr);
			continue;
		}

		if (msg_user(msg) == LINK_PROTOCOL) {
			link_recv_proto_msg(l_ptr, buf);
			head = link_insert_deferred_queue(l_ptr, head);
			tipc_node_unlock(n_ptr);
			continue;
		}
		msg_dbg(msg,"NSEQ<REC<");
		link_state_event(l_ptr, TRAFFIC_MSG_EVT);

		if (link_working_working(l_ptr)) {
			/* Re-insert in front of queue */
			msg_dbg(msg,"RECV-REINS:");
			buf->next = head;
			head = buf;
			tipc_node_unlock(n_ptr);
			continue;
		}
		tipc_node_unlock(n_ptr);
cont:
		buf_discard(buf);
	}
	read_unlock_bh(&tipc_net_lock);
}

/**
 * tipc_link_defer_pkt - Add out-of-sequence message to deferred reception queue
 *
 * Returns increase in queue length (i.e. 0 or 1)
 */

u32 tipc_link_defer_pkt(struct sk_buff **head, struct sk_buff **tail,
			struct sk_buff *buf, u32 buf_seq_no)
{
	struct sk_buff *curr;
	struct sk_buff **prev_link;

	buf->next = NULL;

	/* Handle most likely cases (add to empty queue, or at end of queue) */

	if (!(*head)) {
		*head = *tail = buf;
		return 1;
	}

	if (less(buf_seqno(*tail), buf_seq_no)) {
		(*tail)->next = buf;
		*tail = buf;
		return 1;
	}

	/* Locate insertion point in queue, then insert; discard if duplicate */

	for (prev_link = head, curr = *head; ;
	     prev_link = &curr->next, curr = curr->next) {
		u32 curr_seq_no = buf_seqno(curr);

		if (buf_seq_no == curr_seq_no) {
			buf_discard(buf);
			return 0;
		}
		
		/* Note: here less_eq() is equivalent to less(), but faster */

		if (less_eq(buf_seq_no, curr_seq_no))
			break;
	}

	buf->next = curr;
	*prev_link = buf;
	return 1;
}

/**
 * link_handle_out_of_seq_msg - handle arrival of out-of-sequence packet
 */

static void link_handle_out_of_seq_msg(struct link *l_ptr,
				       struct sk_buff *buf)
{
	u32 seq_no = buf_seqno(buf);

	if (likely(msg_user(buf_msg(buf)) == LINK_PROTOCOL)) {
		link_recv_proto_msg(l_ptr, buf);
		return;
	}

	dbg("rx OOS msg: seq_no %u, expecting %u (%u)\n",
	    seq_no, mod(l_ptr->next_in_no), l_ptr->next_in_no);

	/* Record OOS packet arrival (force mismatch on next timeout) */

	l_ptr->checkpoint--;

	/*
	 * Discard packet if a duplicate; otherwise add it to deferred queue
	 * and notify peer of gap as per protocol specification
	 */

	if (less(seq_no, mod(l_ptr->next_in_no))) {
		l_ptr->stats.duplicates++;
		buf_discard(buf);
		return;
	}

	if (tipc_link_defer_pkt(&l_ptr->oldest_deferred_in,
				&l_ptr->newest_deferred_in,
				buf, seq_no)) {
		l_ptr->deferred_inqueue_sz++;
		l_ptr->stats.deferred_recv++;
		if ((l_ptr->deferred_inqueue_sz % 16) == 1)
			tipc_link_send_proto_msg(l_ptr, STATE_MSG, 0, 0, 0, 0, 0, 0);
	} else
		l_ptr->stats.duplicates++;
}

/*
 * Send protocol message to the other endpoint.
 */
void tipc_link_send_proto_msg(struct link *l_ptr, u32 msg_typ, int probe_msg,
                              u32 gap, u32 tolerance, u32 priority, u32 ack_mtu,
                              int stop)
{
	struct sk_buff *buf = NULL;
	struct tipc_msg *msg = l_ptr->pmsg;
	u32 msg_size = sizeof(l_ptr->proto_msg);

	if (link_blocked(l_ptr))
		return;
	msg_set_type(msg, msg_typ);
	msg_set_net_plane(msg, l_ptr->b_ptr->net_plane);
	msg_set_bcast_ack(msg, l_ptr->owner->bclink.last_in);
	msg_set_last_bcast(msg, tipc_bclink_get_last_sent());

	if (msg_typ == STATE_MSG) {
		u32 next_sent = mod(l_ptr->next_out_no);

		if (!tipc_link_is_up(l_ptr))
			return;
		if (l_ptr->next_out)
			next_sent = buf_seqno(l_ptr->next_out);
		msg_set_next_sent(msg, next_sent);
		if (l_ptr->oldest_deferred_in) {
			u32 rec = buf_seqno(l_ptr->oldest_deferred_in);
			gap = mod(rec - mod(l_ptr->next_in_no));
		}
		msg_set_seq_gap(msg, gap);
		if (gap)
			l_ptr->stats.sent_nacks++;
		msg_set_link_tolerance(msg, tolerance);
		msg_set_linkprio(msg, priority);
		msg_set_max_pkt(msg, ack_mtu);
		msg_set_ack(msg, mod(l_ptr->next_in_no - 1));
		msg_set_probe(msg, probe_msg != 0);
		if (probe_msg) {
			u32 mtu = l_ptr->max_pkt;

			if ((mtu < l_ptr->max_pkt_target) &&
			    link_working_working(l_ptr) &&
			    l_ptr->fsm_msg_cnt) {
				msg_size = (mtu + (l_ptr->max_pkt_target - mtu)/2 + 2) & ~3;
				if (l_ptr->max_pkt_probes == 10) {
					l_ptr->max_pkt_target = (msg_size - 4);
					l_ptr->max_pkt_probes = 0;
					msg_size = (mtu + (l_ptr->max_pkt_target - mtu)/2 + 2) & ~3;
				}
				l_ptr->max_pkt_probes++;
			}

			l_ptr->stats.sent_probes++;
		}
		l_ptr->stats.sent_states++;
	} else {		/* RESET_MSG or ACTIVATE_MSG */
		msg_set_ack(msg, mod(l_ptr->reset_checkpoint - 1));
		msg_set_seq_gap(msg, 0);
		msg_set_next_sent(msg, 1);
		msg_set_stop(msg, stop);
		msg_set_link_tolerance(msg, l_ptr->tolerance);
		msg_set_linkprio(msg, l_ptr->priority);
		msg_set_max_pkt(msg, l_ptr->max_pkt_target);
	}

	msg_set_redundant_link(msg, tipc_node_has_redundant_links(l_ptr->owner));
	msg_set_linkprio(msg, l_ptr->priority);

	/* Ensure sequence number will not fit : */

	msg_set_seqno(msg, mod(l_ptr->next_out_no + (0xffff/2)));

	/* Congestion? */

	if (tipc_bearer_congested(l_ptr->b_ptr, l_ptr)) {
		if (!l_ptr->proto_msg_queue) {
			l_ptr->proto_msg_queue =
				buf_acquire(sizeof(l_ptr->proto_msg));
		}
		buf = l_ptr->proto_msg_queue;
		if (!buf)
			return;
		skb_copy_to_linear_data(buf, msg, sizeof(l_ptr->proto_msg));
		return;
	}
	msg_set_timestamp(msg, jiffies_to_msecs(jiffies));

	/* Message can be sent */

	msg_dbg(msg, ">>");

	buf = buf_acquire(msg_size);
	if (!buf)
		return;

	skb_copy_to_linear_data(buf, msg, sizeof(l_ptr->proto_msg));
	msg_set_size(buf_msg(buf), msg_size);

	if (tipc_bearer_send(l_ptr->b_ptr, buf, &l_ptr->media_addr)) {
		l_ptr->unacked_window = 0;
		buf_discard(buf);
		return;
	}

	/* New congestion */
	tipc_bearer_schedule(l_ptr->b_ptr, l_ptr);
	l_ptr->proto_msg_queue = buf;
	l_ptr->stats.bearer_congs++;
}

/*
 * Receive protocol message :
 * Note that network plane id propagates through the network, and may
 * change at any time. The node with lowest address rules
 */

static void link_recv_proto_msg(struct link *l_ptr, struct sk_buff *buf)
{
	u32 rec_gap = 0;
	u32 max_pkt_info;
	u32 max_pkt_ack;
	u32 msg_tol;
	struct tipc_msg *msg = buf_msg(buf);

	dbg("AT(%u):", jiffies_to_msecs(jiffies));
	msg_dbg(msg, "<<");
	if (link_blocked(l_ptr))
		goto exit;

	/* record unnumbered packet arrival (force mismatch on next timeout) */

	l_ptr->checkpoint--;

	if (l_ptr->b_ptr->net_plane != msg_net_plane(msg))
		if (tipc_own_addr > msg_prevnode(msg))
			l_ptr->b_ptr->net_plane = msg_net_plane(msg);

	l_ptr->owner->permit_changeover = msg_redundant_link(msg);

	switch (msg_type(msg)) {

	case RESET_MSG:
		if (!link_working_unknown(l_ptr) &&
		    (l_ptr->peer_session != INVALID_SESSION)) {
			if (msg_session(msg) == l_ptr->peer_session) {
				dbg("Duplicate RESET: %u<->%u\n",
				    msg_session(msg), l_ptr->peer_session);
				break; /* duplicate: ignore */
			}
		}
                if (msg_stop(msg)) {
                        tipc_link_reset(l_ptr);
                        l_ptr->blocked = 1;
                        tipc_k_signal((Handler)link_remote_delete,(unsigned long)l_ptr);
                        break;
                }

		/* fall thru' */
	case ACTIVATE_MSG:
		/* Update link settings according other endpoint's values */

		strcpy((strrchr(l_ptr->name, ':') + 1), (char *)msg_data(msg));

		if ((msg_tol = msg_link_tolerance(msg)) &&
		    (msg_tol > l_ptr->tolerance))
			link_set_supervision_props(l_ptr, msg_tol);

		if (msg_linkprio(msg) > l_ptr->priority)
			l_ptr->priority = msg_linkprio(msg);

		max_pkt_info = msg_max_pkt(msg);
		if (max_pkt_info) {
			if (max_pkt_info < l_ptr->max_pkt_target)
				l_ptr->max_pkt_target = max_pkt_info;
			if (l_ptr->max_pkt > l_ptr->max_pkt_target)
				l_ptr->max_pkt = l_ptr->max_pkt_target;
		} else {
			l_ptr->max_pkt = l_ptr->max_pkt_target;
		}
		l_ptr->owner->bclink.supported = 
			in_own_cluster(l_ptr->owner->elm.addr) &&
			(max_pkt_info != 0);

		link_state_event(l_ptr, msg_type(msg));

		l_ptr->peer_session = msg_session(msg);
		l_ptr->peer_bearer_id = msg_bearer_id(msg);

		/* Synchronize broadcast link information */

		if (!tipc_node_has_redundant_links(l_ptr->owner)) {
			l_ptr->owner->bclink.last_sent =
				l_ptr->owner->bclink.last_in =
				msg_last_bcast(msg);
			l_ptr->owner->bclink.oos_state = 0;
		}
		break;
	case STATE_MSG:

		if ((msg_tol = msg_link_tolerance(msg)))
			link_set_supervision_props(l_ptr, msg_tol);

		if (msg_linkprio(msg) &&
		    (msg_linkprio(msg) != l_ptr->priority)) {
			warn("Resetting link <%s>, priority change %u->%u\n",
			     l_ptr->name, l_ptr->priority, msg_linkprio(msg));
			l_ptr->priority = msg_linkprio(msg);
			tipc_link_reset(l_ptr); /* Enforce change to take effect */
			break;
		}
		link_state_event(l_ptr, TRAFFIC_MSG_EVT);
		l_ptr->stats.recv_states++;
		if (link_reset_unknown(l_ptr))
			break;

		if (less_eq(mod(l_ptr->next_in_no), msg_next_sent(msg))) {
			rec_gap = mod(msg_next_sent(msg) -
				      mod(l_ptr->next_in_no));
		}

		max_pkt_ack = msg_max_pkt(msg);
		if (max_pkt_ack > l_ptr->max_pkt) {
			dbg("Link <%s> updated MTU %u -> %u\n",
			    l_ptr->name, l_ptr->max_pkt, max_pkt_ack);
			l_ptr->max_pkt = max_pkt_ack;
			l_ptr->max_pkt_probes = 0;
		}

		max_pkt_ack = 0;
		if (msg_probe(msg)) {
			l_ptr->stats.recv_probes++;
			if (msg_size(msg) > sizeof(l_ptr->proto_msg)) {
				max_pkt_ack = msg_size(msg);
			}
		}

		/* Protocol message before retransmits, reduce loss risk */

		if (l_ptr->owner->bclink.supported)
			tipc_bclink_update_link_state(l_ptr->owner,
						      msg_last_bcast(msg));

		if (rec_gap || (msg_probe(msg))) {
			tipc_link_send_proto_msg(l_ptr, STATE_MSG,
					    0, rec_gap, 0, 0, max_pkt_ack, 0);
		}
		if (msg_seq_gap(msg)) {
			msg_dbg(msg, "With Gap:");
			l_ptr->stats.recv_nacks++;
			tipc_link_retransmit(l_ptr, l_ptr->first_out,
					     msg_seq_gap(msg));
		}
		break;
	default:
		msg_dbg(buf_msg(buf), "<DISCARDING UNKNOWN<");
	}
exit:
	buf_discard(buf);
}

/**
 * buf_extract - extracts embedded TIPC message from another message
 * @skb: encapsulating message buffer
 * @from_pos: offset to extract from
 *
 * Returns a new message buffer containing an embedded message.  The 
 * encapsulating message itself is left unchanged.
 */

static struct sk_buff *buf_extract(struct sk_buff *skb, u32 from_pos)
{
	struct tipc_msg *msg = (struct tipc_msg *)(skb->data + from_pos);
	u32 size = msg_size(msg);
	struct sk_buff *eb;

	eb = buf_acquire(size);
	if (eb)
		skb_copy_to_linear_data(eb, msg, size);
	return eb;
}

#ifdef CONFIG_TIPC_MULTIPLE_LINKS

/*
 * link_tunnel(): Send one message via a link belonging to another bearer.
 * Owner node is locked.
 */
static void link_tunnel(struct link *l_ptr, struct tipc_msg *tunnel_hdr, 
			struct tipc_msg  *msg, u32 selector)
{
	struct link *tunnel;
	struct sk_buff *buf;
	u32 length = msg_size(msg);

	tunnel = l_ptr->owner->active_links[selector & 1];
	if (!tipc_link_is_up(tunnel)) {
		warn("Link changeover error, "
		     "tunnel link no longer available\n");
		return;
	}
	msg_set_size(tunnel_hdr, length + INT_H_SIZE);
	buf = buf_acquire(length + INT_H_SIZE);
	if (!buf) {
		warn("Link changeover error, "
		     "unable to send tunnel msg\n");
		return;
	}
	skb_copy_to_linear_data(buf, tunnel_hdr, INT_H_SIZE);
	skb_copy_to_linear_data_offset(buf, INT_H_SIZE, msg, length);
	dbg("%c->%c:", l_ptr->b_ptr->net_plane, tunnel->b_ptr->net_plane);
	msg_dbg(buf_msg(buf), ">SEND>");
	tipc_link_send_buf(tunnel, buf);
}



/*
 * changeover(): Send whole message queue via the remaining link
 *               Owner node is locked.
 */

void tipc_link_changeover(struct link *l_ptr)
{
	u32 msgcount = l_ptr->out_queue_size;
	struct sk_buff *crs = l_ptr->first_out;
	struct link *tunnel = l_ptr->owner->active_links[0];
	struct tipc_msg tunnel_hdr;
	int split_bundles;

	if (!tunnel)
		return;

	if (!l_ptr->owner->permit_changeover) {
		warn("Link changeover error, "
		     "peer did not permit changeover\n");
		return;
	}

	tipc_msg_init(&tunnel_hdr, CHANGEOVER_PROTOCOL, ORIGINAL_MSG,
		      INT_H_SIZE, l_ptr->addr);
	msg_set_bearer_id(&tunnel_hdr, l_ptr->peer_bearer_id);
	msg_set_msgcnt(&tunnel_hdr, msgcount);
	dbg("Link changeover requires %u tunnel messages\n", msgcount);

	if (!l_ptr->first_out) {
		struct sk_buff *buf;

		buf = buf_acquire(INT_H_SIZE);
		if (buf) {
			skb_copy_to_linear_data(buf, &tunnel_hdr, INT_H_SIZE);
			msg_set_size(&tunnel_hdr, INT_H_SIZE);
			dbg("%c->%c:", l_ptr->b_ptr->net_plane,
			    tunnel->b_ptr->net_plane);
			msg_dbg(&tunnel_hdr, "EMPTY>SEND>");
			tipc_link_send_buf(tunnel, buf);
		} else {
			warn("Link changeover error, "
			     "unable to send changeover msg\n");
		}
		return;
	}

	split_bundles = (l_ptr->owner->active_links[0] !=
			 l_ptr->owner->active_links[1]);

	while (crs) {
		struct tipc_msg *msg = buf_msg(crs);

		if ((msg_user(msg) == MSG_BUNDLER) && split_bundles) {
			u32 bundle_size = msg_msgcnt(msg);
			struct tipc_msg *m = msg_get_wrapped(msg);
			unchar* pos = (unchar*)m;

			while (bundle_size--) {
				msg_set_seqno(m,msg_seqno(msg));
				link_tunnel(l_ptr, &tunnel_hdr, m,
					    msg_link_selector(m));
				pos += align(msg_size(m));
				m = (struct tipc_msg *)pos;
			}
		} else {
			link_tunnel(l_ptr, &tunnel_hdr, msg,
				    msg_link_selector(msg));
		}
		crs = crs->next;
	}
}

void tipc_link_send_duplicate(struct link *l_ptr, struct link *tunnel)
{
	struct sk_buff *iter;
	struct tipc_msg tunnel_hdr;

	tipc_msg_init(&tunnel_hdr, CHANGEOVER_PROTOCOL, DUPLICATE_MSG,
		      INT_H_SIZE, l_ptr->addr);
	msg_set_msgcnt(&tunnel_hdr, l_ptr->out_queue_size);
	msg_set_bearer_id(&tunnel_hdr, l_ptr->peer_bearer_id);
	iter = l_ptr->first_out;
	while (iter) {
		struct sk_buff *outbuf;
		struct tipc_msg *msg = buf_msg(iter);
		u32 length = msg_size(msg);

		if (msg_user(msg) == MSG_BUNDLER)
			msg_set_type(msg, CLOSED_MSG);
		msg_set_ack(msg, mod(l_ptr->next_in_no - 1));	/* Update */
		msg_set_bcast_ack(msg, l_ptr->owner->bclink.last_in);
		msg_set_size(&tunnel_hdr, length + INT_H_SIZE);
		outbuf = buf_acquire(length + INT_H_SIZE);
		if (outbuf == NULL) {
			warn("Link changeover error, "
			     "unable to send duplicate msg\n");
			return;
		}
		skb_copy_to_linear_data(outbuf, &tunnel_hdr, INT_H_SIZE);
		skb_copy_to_linear_data_offset(outbuf, INT_H_SIZE, iter->data,
					       length);
		dbg("%c->%c:", l_ptr->b_ptr->net_plane,
		    tunnel->b_ptr->net_plane);
		msg_dbg(buf_msg(outbuf), ">SEND>");
		tipc_link_send_buf(tunnel, outbuf);
		if (!tipc_link_is_up(l_ptr))
			return;
		iter = iter->next;
	}
}

/*
 *  link_recv_changeover_msg(): Receive tunneled packet sent
 *  via other link. Node is locked. Return extracted buffer.
 */

static int link_recv_changeover_msg(struct link **l_ptr,
				    struct sk_buff **buf)
{
	struct sk_buff *tunnel_buf = *buf;
	struct link *dest_link;
	struct tipc_msg *msg;
	struct tipc_msg *tunnel_msg = buf_msg(tunnel_buf);
	u32 msg_typ = msg_type(tunnel_msg);
	u32 msg_count = msg_msgcnt(tunnel_msg);

	dest_link = (*l_ptr)->owner->links[msg_bearer_id(tunnel_msg)];
	if (!dest_link) {
		msg_dbg(tunnel_msg, "NOLINK/<REC<");
		goto exit;
	}
	if (dest_link == *l_ptr) {
		err("Unexpected changeover message on link <%s>\n",
		    (*l_ptr)->name);
		goto exit;
	}
	dbg("%c<-%c:", dest_link->b_ptr->net_plane,
	    (*l_ptr)->b_ptr->net_plane);
	*l_ptr = dest_link;
	msg = msg_get_wrapped(tunnel_msg);

	if (msg_typ == DUPLICATE_MSG) {
		if (less(msg_seqno(msg), mod(dest_link->next_in_no))) {
			msg_dbg(tunnel_msg, "DROP/<REC<");
			goto exit;
		}
		*buf = buf_extract(tunnel_buf,INT_H_SIZE);
		if (*buf == NULL) {
			warn("Link changeover error, duplicate msg dropped\n");
			goto exit;
		}
		msg_dbg(tunnel_msg, "TNL<REC<");
		buf_discard(tunnel_buf);
		return 1;
	}

	/* First original message ?: */

	if (tipc_link_is_up(dest_link)) {
		msg_dbg(tunnel_msg, "UP/FIRST/<REC<");
		info("Resetting link <%s>, changeover initiated by peer\n",
		     dest_link->name);
		tipc_link_reset(dest_link);
		dest_link->exp_msg_count = msg_count;
		dbg("Expecting %u tunnelled messages\n", msg_count);
		if (!msg_count)
			goto exit;
	} else if (dest_link->exp_msg_count == START_CHANGEOVER) {
		msg_dbg(tunnel_msg, "BLK/FIRST/<REC<");
		dest_link->exp_msg_count = msg_count;
		dbg("Expecting %u tunnelled messages\n", msg_count);
		if (!msg_count)
			goto exit;
	}

	/* Receive original message */

	if (dest_link->exp_msg_count == 0) {
		warn("Link switchover error, "
		     "got too many tunnelled messages\n");
		msg_dbg(tunnel_msg, "OVERDUE/DROP/<REC<");
		dbg_print_link(dest_link, "LINK:");
		goto exit;
	}
	dest_link->exp_msg_count--;
	if (less(msg_seqno(msg), dest_link->reset_checkpoint)) {
		msg_dbg(tunnel_msg, "DROP/DUPL/<REC<");
		goto exit;
	} else {
		*buf = buf_extract(tunnel_buf, INT_H_SIZE);
		if (*buf != NULL) {
			msg_dbg(tunnel_msg, "TNL<REC<");
			buf_discard(tunnel_buf);
			return 1;
		} else {
			warn("Link changeover error, original msg dropped\n");
		}
	}
exit:
	*buf = NULL;
	buf_discard(tunnel_buf);
	return 0;
}

#endif

/*
 *  Bundler functionality:
 */
void tipc_link_recv_bundle(struct sk_buff *buf)
{
	u32 msgcount = msg_msgcnt(buf_msg(buf));
	u32 pos = INT_H_SIZE;
	struct sk_buff *obuf;
	struct tipc_msg *omsg;

	msg_dbg(buf_msg(buf), "<BNDL<: ");
	while (msgcount--) {
		obuf = buf_extract(buf, pos);
		if (obuf == NULL) {
			warn("Link unable to unbundle message(s)\n");
			break;
		}
		omsg = buf_msg(obuf);
		pos += align(msg_size(omsg));
		msg_dbg(omsg, "     /");
		msg_set_destnode_cache(omsg, tipc_own_addr);
		tipc_net_route_msg(obuf);
	}
	buf_discard(buf);
}

/*
 *  Fragmentation/defragmentation:
 */


/*
 * tipc_link_send_long_buf: Entry for buffers needing fragmentation.
 * The buffer is complete, inclusive total message length.
 * Returns user data length.
 */
int tipc_link_send_long_buf(struct link *l_ptr, struct sk_buff *buf)
{
	struct tipc_msg *inmsg = buf_msg(buf);
	struct tipc_msg fragm_hdr;
	u32 insize = msg_size(inmsg);
	u32 dsz = msg_data_sz(inmsg);
	unchar *crs = buf->data;
	u32 rest = insize;
	u32 pack_sz = l_ptr->max_pkt;
	u32 fragm_sz = pack_sz - INT_H_SIZE;
	u32 fragm_no = 1;
	u32 destaddr;

	if (msg_short(inmsg))
		destaddr = l_ptr->addr;
	else
		destaddr = msg_destnode(inmsg);

	if (msg_routed(inmsg))
		msg_set_prevnode(inmsg, tipc_own_addr);

	/* Prepare reusable fragment header: */

	tipc_msg_init(&fragm_hdr, MSG_FRAGMENTER, FIRST_FRAGMENT,
		      INT_H_SIZE, destaddr);
	msg_set_link_selector(&fragm_hdr, msg_link_selector(inmsg));
	msg_set_fragm_msg_no(&fragm_hdr, 
			     atomic_inc_return(&link_fragm_msg_no) & 0xffff);
	msg_set_fragm_no(&fragm_hdr, fragm_no);
	l_ptr->stats.sent_fragmented++;

	/* Chop up message: */

	while (rest > 0) {
		struct sk_buff *fragm;

		if (rest <= fragm_sz) {
			fragm_sz = rest;
			msg_set_type(&fragm_hdr, LAST_FRAGMENT);
		}
		fragm = buf_acquire(fragm_sz + INT_H_SIZE);
		if (fragm == NULL) {
			warn("Link unable to fragment message\n");
			dsz = -ENOMEM;
			goto exit;
		}
		msg_set_size(&fragm_hdr, fragm_sz + INT_H_SIZE);
		skb_copy_to_linear_data(fragm, &fragm_hdr, INT_H_SIZE);
		skb_copy_to_linear_data_offset(fragm, INT_H_SIZE, crs,
					       fragm_sz);

		/*  Send queued messages first, if any: */

		l_ptr->stats.sent_fragments++;
		tipc_link_send_buf(l_ptr, fragm);
		if (!tipc_link_is_up(l_ptr))
			return dsz;
		msg_set_fragm_no(&fragm_hdr, ++fragm_no);
		rest -= fragm_sz;
		crs += fragm_sz;
		msg_set_type(&fragm_hdr, FRAGMENT);
	}
exit:
	buf_discard(buf);
	return dsz;
}

/* 
 * A partially reassembled message must store certain values so that subsequent 
 * fragments can be incorporated correctly.  The following routines store these
 * values in temporarily available fields in the partially reassembled message,
 * thereby making dynamic memory allocation unecessary.
 */

static inline u32 get_long_msg_orig(struct sk_buff *buf)
{
	return (u32)(unsigned long)buf_handle(buf);
}

static inline void set_long_msg_orig(struct sk_buff *buf, u32 orig)
{
	 buf_set_handle(buf, (void *)(unsigned long)orig);
}

static inline u32 get_long_msg_seqno(struct sk_buff *buf)
{
	return buf_seqno(buf);
}

static inline void set_long_msg_seqno(struct sk_buff *buf, u32 seqno)
{
	msg_set_seqno(buf_msg(buf), seqno);
}

static inline u32 get_fragm_size(struct sk_buff *buf)
{
	return msg_ack(buf_msg(buf));
}

static inline void set_fragm_size(struct sk_buff *buf, u32 sz)
{
	msg_set_ack(buf_msg(buf), sz);
}

static inline u32 get_expected_frags(struct sk_buff *buf)
{
	return msg_bcast_ack(buf_msg(buf));
}

static inline void set_expected_frags(struct sk_buff *buf, u32 exp)
{
	msg_set_bcast_ack(buf_msg(buf), exp);
}

static inline u32 get_timer_cnt(struct sk_buff *buf)
{
	return msg_reroute_cnt(buf_msg(buf));
}

static inline void reset_timer_cnt(struct sk_buff *buf)
{
	msg_reset_reroute_cnt(buf_msg(buf));
}

static inline void incr_timer_cnt(struct sk_buff *buf)
{
	msg_incr_reroute_cnt(buf_msg(buf));
}

/*
 * tipc_link_recv_fragment(): Called with node lock on. Returns
 * the reassembled buffer if message is complete.
 */
int tipc_link_recv_fragment(struct sk_buff **pending, struct sk_buff **fb,
			    struct tipc_msg **m)
{
	struct sk_buff *pbuf = *pending;
	struct sk_buff *fbuf = *fb;
	struct sk_buff *prev = NULL;
	struct tipc_msg *fragm = buf_msg(fbuf);
	u32 long_msg_orig = msg_orignode(fragm);
	u32 long_msg_seq_no = msg_fragm_msg_no(fragm);

	*fb = NULL;
	msg_dbg(fragm,"FRG<REC<");

	/* Is there an incomplete message waiting for this fragment? */

	while (pbuf && ((get_long_msg_orig(pbuf) != long_msg_orig)
			|| (get_long_msg_seqno(pbuf) != long_msg_seq_no))) {
		prev = pbuf;
		pbuf = pbuf->next;
	}

	if (!pbuf && (msg_type(fragm) == FIRST_FRAGMENT)) {
		struct tipc_msg *imsg = (struct tipc_msg *)msg_data(fragm);
		u32 msg_sz = msg_size(imsg);
		u32 fragm_sz = msg_data_sz(fragm);
		u32 exp_fragm_cnt = msg_sz/fragm_sz + !!(msg_sz % fragm_sz);
		u32 max =  TIPC_MAX_USER_MSG_SIZE + LONG_H_SIZE;

		if (msg_type(imsg) == TIPC_MCAST_MSG)
			max = TIPC_MAX_USER_MSG_SIZE + MCAST_H_SIZE;
		if (msg_size(imsg) > max) {
			msg_dbg(fragm,"<REC<Oversized: ");
			buf_discard(fbuf);
			return 0;
		}
		pbuf = buf_acquire(msg_size(imsg));
		if (pbuf != NULL) {
			pbuf->next = *pending;
			*pending = pbuf;
			skb_copy_to_linear_data(pbuf, imsg,
						msg_data_sz(fragm));

			/*  Prepare buffer for subsequent fragments. */

			set_long_msg_orig(pbuf, long_msg_orig); 
			set_long_msg_seqno(pbuf, long_msg_seq_no); 
			set_fragm_size(pbuf,fragm_sz); 
			set_expected_frags(pbuf,exp_fragm_cnt - 1); 
			reset_timer_cnt(pbuf);
		} else {
			warn("Link unable to reassemble fragmented message\n");
		}
		buf_discard(fbuf);
		return 0;
	} else if (pbuf && (msg_type(fragm) != FIRST_FRAGMENT)) {
		u32 dsz = msg_data_sz(fragm);
		u32 fsz = get_fragm_size(pbuf);
		u32 crs = ((msg_fragm_no(fragm) - 1) * fsz);
		u32 exp_frags = get_expected_frags(pbuf) - 1;
		skb_copy_to_linear_data_offset(pbuf, crs,
					       msg_data(fragm), dsz);
		buf_discard(fbuf);
		reset_timer_cnt(pbuf);

		/* Is message complete? */

		if (exp_frags == 0) {
			if (prev)
				prev->next = pbuf->next;
			else
				*pending = pbuf->next;
			*fb = pbuf;
			*m = buf_msg(pbuf);
			return 1;
		}
		set_expected_frags(pbuf,exp_frags);
		return 0;
	}
	dbg(" Discarding orphan fragment %x\n",fbuf);
	msg_dbg(fragm,"ORPHAN:");
	dbg("Pending long buffers:\n");
	dbg_print_buf_chain(*pending);
	buf_discard(fbuf);
	return 0;
}

/**
 * link_check_defragm_bufs - flush stale incoming message fragments
 * @l_ptr: pointer to link
 */

static void link_check_defragm_bufs(struct link *l_ptr)
{
	struct sk_buff *prev = NULL;
	struct sk_buff *next = NULL;
	struct sk_buff *buf = l_ptr->defragm_buf;

	if (!buf)
		return;
	if (!link_working_working(l_ptr))
		return;
	while (buf) {
		u32 cnt = get_timer_cnt(buf);

		next = buf->next;
		if (cnt < 4) {
			incr_timer_cnt(buf);
			prev = buf;
		} else {
			dbg(" Discarding incomplete long buffer\n");
			msg_dbg(buf_msg(buf), "LONG:");
			dbg_print_link(l_ptr, "curr:");
			dbg("Pending long buffers:\n");
			dbg_print_buf_chain(l_ptr->defragm_buf);
			if (prev)
				prev->next = buf->next;
			else
				l_ptr->defragm_buf = buf->next;
			buf_discard(buf);
		}
		buf = next;
	}
}



static void link_set_supervision_props(struct link *l_ptr, u32 tolerance)
{
	l_ptr->tolerance = tolerance;
	l_ptr->continuity_interval =
		((tolerance / 4) > 500) ? 500 : tolerance / 4;
	l_ptr->abort_limit = tolerance / (l_ptr->continuity_interval / 4);
}


void tipc_link_set_queue_limits(struct link *l_ptr, u32 window)
{
	/* Data messages from this node, inclusive FIRST_FRAGM */
	l_ptr->queue_limit[TIPC_LOW_IMPORTANCE] = window;
	l_ptr->queue_limit[TIPC_MEDIUM_IMPORTANCE] = (window / 3) * 4;
	l_ptr->queue_limit[TIPC_HIGH_IMPORTANCE] = (window / 3) * 5;
	l_ptr->queue_limit[TIPC_CRITICAL_IMPORTANCE] = (window / 3) * 6;
	/* Transiting data messages,inclusive FIRST_FRAGM */
	l_ptr->queue_limit[TIPC_LOW_IMPORTANCE + 4] = 300;
	l_ptr->queue_limit[TIPC_MEDIUM_IMPORTANCE + 4] = 600;
	l_ptr->queue_limit[TIPC_HIGH_IMPORTANCE + 4] = 900;
	l_ptr->queue_limit[TIPC_CRITICAL_IMPORTANCE + 4] = 1200;
	l_ptr->queue_limit[CONN_MANAGER] = 1200;
	l_ptr->queue_limit[ROUTE_DISTRIBUTOR] = 1200;
	l_ptr->queue_limit[CHANGEOVER_PROTOCOL] = 2500;
	l_ptr->queue_limit[NAME_DISTRIBUTOR] = 3000;
	/* FRAGMENT and LAST_FRAGMENT packets */
	l_ptr->queue_limit[MSG_FRAGMENTER] = 4000;
}

#ifdef CONFIG_TIPC_CONFIG_SERVICE

/**
 * link_find_link - locate link by name
 * @name - ptr to link name string
 * @node - ptr to area to be filled with ptr to associated node
 *
 * Caller must hold 'tipc_net_lock' to ensure node and bearer are not deleted;
 * this also prevents link deletion.
 *
 * Returns pointer to link (or 0 if invalid link name).
 */

static struct link *link_find_link(const char *name, struct tipc_node **node)
{
	struct link_name link_name_parts;
	struct bearer *b_ptr;
	struct link *l_ptr;

	if (!link_name_validate(name, &link_name_parts))
		return NULL;

	b_ptr = tipc_bearer_find(link_name_parts.if_local);
	if (!b_ptr)
		return NULL;

	*node = tipc_net_find_node(link_name_parts.addr_peer); 
	if (!*node)
		return NULL;

	l_ptr = (*node)->links[b_ptr->identity];
	if (!l_ptr || strcmp(l_ptr->name, name))
		return NULL;

	return l_ptr;
}


/**
 * value_is_valid -- check if priority/link tolerance/window is within range
 *
 * @cmd - value type (TIPC_CMD_SET_LINK_*)
 * @new_value - the new value
 *
 * Returns 1 if value is within range, 0 if not.
 */
static int value_is_valid(u16 cmd, u32 new_value)
{
	switch (cmd) {
	case TIPC_CMD_SET_LINK_TOL:
		return (new_value >= TIPC_MIN_LINK_TOL) &&
			(new_value <= TIPC_MAX_LINK_TOL);
	case TIPC_CMD_SET_LINK_PRI:
		return (new_value >= TIPC_MIN_LINK_PRI) &&
			(new_value <= TIPC_MAX_LINK_PRI);
	case TIPC_CMD_SET_LINK_WINDOW:
		return (new_value >= TIPC_MIN_LINK_WIN) &&
			(new_value <= TIPC_MAX_LINK_WIN);
	}
	return 0;
}


/**
 * cmd_set_link_value - change priority/tolerance/window size of link, bearer or media
 * @name - ptr to link, bearer or media name string
 * @new_value - the new link priority or new bearer default link priority
 * @cmd - which link/bearer property to set (TIPC_CMD_SET_LINK_*)
 *
 * Caller must hold 'tipc_net_lock' to ensure link/bearer are not deleted.
 *
 * Returns 0 if value updated and negative value on error.
 */
static int cmd_set_link_value(const char *name, u32 new_value, u16 cmd)
{
	struct tipc_node *node;
	struct link *l_ptr;
	struct bearer *b_ptr;
	struct tipc_media *m_ptr;

	l_ptr = link_find_link(name, &node);
	if (l_ptr) {
		/*
		 * acquire node lock for tipc_link_send_proto_msg().
		 * see "TIPC locking policy" in tipc_net.c.
		 */
		tipc_node_lock(node);
		switch (cmd) {
		case TIPC_CMD_SET_LINK_TOL:
			link_set_supervision_props(l_ptr, new_value);
			tipc_link_send_proto_msg(l_ptr, STATE_MSG,
				0, 0, new_value, 0, 0, 0);
			break;
		case TIPC_CMD_SET_LINK_PRI:
			l_ptr->priority = new_value;
			tipc_link_send_proto_msg(l_ptr, STATE_MSG,
				0, 0, 0, new_value, 0, 0);
			break;
		case TIPC_CMD_SET_LINK_WINDOW:
			tipc_link_set_queue_limits(l_ptr, new_value);
			break;
		}
		tipc_node_unlock(node);
		return 0;
	}

	b_ptr = tipc_bearer_find(name);
	if (b_ptr) {
		switch (cmd) {
		case TIPC_CMD_SET_LINK_TOL:
			b_ptr->tolerance = new_value;
			return 0;
		case TIPC_CMD_SET_LINK_PRI:
			b_ptr->priority = new_value;
			return 0;
		case TIPC_CMD_SET_LINK_WINDOW:
			b_ptr->window = new_value;
			return 0;
		}
		return -EINVAL;
	}

	m_ptr = tipc_media_find_name(name);
	if (!m_ptr)
		return -ENODEV;
	switch (cmd) {
	case TIPC_CMD_SET_LINK_TOL:
		m_ptr->tolerance = new_value;
		return 0;
	case TIPC_CMD_SET_LINK_PRI:
		m_ptr->priority = new_value;
		return 0;
	case TIPC_CMD_SET_LINK_WINDOW:
		m_ptr->window = new_value;
		return 0;
	}
	return -EINVAL;
}


struct sk_buff *tipc_link_cmd_config(const void *req_tlv_area, int req_tlv_space,
				     u16 cmd)
{
	struct tipc_link_config *args;
	u32 new_value;
	int res;

	if (!TLV_CHECK(req_tlv_area, req_tlv_space, TIPC_TLV_LINK_CONFIG))
		return tipc_cfg_reply_error_string(TIPC_CFG_TLV_ERROR);

	args = (struct tipc_link_config *)TLV_DATA(req_tlv_area);
	new_value = ntohl(args->value);

	if (!value_is_valid(cmd, new_value))
		return tipc_cfg_reply_error_string("cannot change, value invalid");

	if (!strcmp(args->name, tipc_bclink_name)) {
		if ((cmd == TIPC_CMD_SET_LINK_WINDOW) &&
		    (tipc_bclink_set_queue_limits(new_value) == 0))
			return tipc_cfg_reply_none();
		return tipc_cfg_reply_error_string(TIPC_CFG_NOT_SUPPORTED
						   " (cannot change setting on broadcast link)");
	}

	read_lock_bh(&tipc_net_lock);
	res = cmd_set_link_value(args->name, new_value, cmd);
	read_unlock_bh(&tipc_net_lock);
	if (res)
		return tipc_cfg_reply_error_string("cannot change link setting");

	return tipc_cfg_reply_none();
}

#endif

/**
 * link_reset_statistics - reset link statistics
 * @l_ptr: pointer to link
 */

static void link_reset_statistics(struct link *l_ptr)
{
	memset(&l_ptr->stats, 0, sizeof(l_ptr->stats));
	l_ptr->stats.sent_info = l_ptr->next_out_no;
	l_ptr->stats.recv_info = l_ptr->next_in_no;
}

#ifdef CONFIG_TIPC_CONFIG_SERVICE

struct sk_buff *tipc_link_cmd_reset_stats(const void *req_tlv_area, int req_tlv_space)
{
	char *link_name;
	struct link *l_ptr;
	struct tipc_node *node;

	if (!TLV_CHECK(req_tlv_area, req_tlv_space, TIPC_TLV_LINK_NAME))
		return tipc_cfg_reply_error_string(TIPC_CFG_TLV_ERROR);

	link_name = (char *)TLV_DATA(req_tlv_area);
	if (!strcmp(link_name, tipc_bclink_name)) {
		if (tipc_bclink_reset_stats())
			return tipc_cfg_reply_error_string("link not found");
		return tipc_cfg_reply_none();
	}

	read_lock_bh(&tipc_net_lock);
	l_ptr = link_find_link(link_name, &node);
	if (!l_ptr) {
		read_unlock_bh(&tipc_net_lock);
		return tipc_cfg_reply_error_string("link not found");
	}

	tipc_node_lock(node);
	link_reset_statistics(l_ptr);
	tipc_node_unlock(node);
	read_unlock_bh(&tipc_net_lock);
	return tipc_cfg_reply_none();
}

#ifdef PROTO_MULTI_DISCOVERY_OBJECT
struct sk_buff *tipc_link_cmd_delete(const void *req_tlv_area, int req_tlv_space)
{
        char *cmd_str;
	char *link_name;
	struct link *l_ptr,*temp_l_ptr;
	struct tipc_node *n_ptr;
        struct bearer *b_ptr;
	char *if_name,*domain_str;
	char  cmd[TIPC_MAX_LINK_NAME + 1];
        u32 domain,zone,cluster,node;

	if (!TLV_CHECK(req_tlv_area, req_tlv_space, TIPC_TLV_LINK_NAME))
		return tipc_cfg_reply_error_string(TIPC_CFG_TLV_ERROR);

        cmd_str = (char*) TLV_DATA(req_tlv_area);
        strncpy(cmd,cmd_str,sizeof(cmd));

	link_name = cmd_str;
	if (!strcmp(link_name, tipc_bclink_name)) {
		if (tipc_bclink_reset_stats())
			return tipc_cfg_reply_error_string("link not found");
		return tipc_cfg_reply_none();
	}

        write_lock_bh(&tipc_net_lock);

        /* Scope comprising several links ? */

        if (strchr(link_name,'/') != NULL)
                goto error;

        if (strchr(link_name,'-') == NULL) {

                if_name = cmd_str;

                domain_str = strchr(if_name,',');
                if (domain_str == NULL)
                        goto error;
                *domain_str = 0;
                domain_str++;

                if (sscanf(domain_str,"%u.%u.%u",&zone,&cluster,&node) != 3)
                        goto error;

                domain = tipc_addr(zone,cluster,node);

                if (!tipc_addr_domain_valid(domain))
                        goto error;

                b_ptr = tipc_bearer_find(if_name);

                if (b_ptr == NULL) 
                        goto error;
        } else {
                l_ptr = link_find_link(link_name, &n_ptr); 
                if (!l_ptr) 
                        goto error;
                domain = l_ptr->addr;
                b_ptr = l_ptr->b_ptr;
        }

        if (in_own_cluster(domain))
                goto error;

	spin_lock_bh(&b_ptr->publ.lock);

        tipc_bearer_remove_discoverer(b_ptr,domain);

	list_for_each_entry_safe(l_ptr, temp_l_ptr, &b_ptr->links, link_list) {

                if (tipc_in_scope(domain,l_ptr->addr)) {
                        if (in_own_cluster(l_ptr->addr))
                                continue;
                        n_ptr = l_ptr->owner;
                        tipc_node_lock(n_ptr);
                        tipc_link_reset(l_ptr);

                        /* Tell other end to not re-establish */

                        tipc_link_send_proto_msg(l_ptr,RESET_MSG, 
                                                 0, 0, 0, 0, 0, 1);
                        l_ptr->blocked = 1;
                        tipc_node_unlock(n_ptr);
                        tipc_link_delete(l_ptr);
                }
	}
	spin_unlock_bh(&b_ptr->publ.lock);
	write_unlock_bh(&tipc_net_lock);
	return tipc_cfg_reply_none();

 error:
	write_unlock_bh(&tipc_net_lock);
        return tipc_cfg_reply_error_string(TIPC_CFG_TLV_ERROR);
}
#endif

/**
 * percent - convert count to a percentage of total (rounding up or down)
 */

static u32 percent(u32 count, u32 total)
{
	return (count * 100 + (total / 2)) / total;
}

/**
 * tipc_link_stats - print link statistics
 * @name: link name
 * @buf: print buffer area
 * @buf_size: size of print buffer area
 *
 * Returns length of print buffer data string (or 0 if error)
 */

static int tipc_link_stats(const char *name, char *buf, const u32 buf_size)
{
	struct print_buf pb;
	struct link *l_ptr;
	struct tipc_node *node;
	char *status;
	u32 profile_total = 0;

	if (!strcmp(name, tipc_bclink_name))
		return tipc_bclink_stats(buf, buf_size);

	tipc_printbuf_init(&pb, buf, buf_size);

	read_lock_bh(&tipc_net_lock);
	l_ptr = link_find_link(name, &node);
	if (!l_ptr) {
		read_unlock_bh(&tipc_net_lock);
		return 0;
	}
	tipc_node_lock(node);

	if (tipc_link_is_active(l_ptr))
		status = "ACTIVE";
	else if (tipc_link_is_up(l_ptr))
		status = "STANDBY";
	else
		status = "DEFUNCT";
	tipc_printf(&pb, "Link <%s>\n"
			 "  %s  MTU:%u  Priority:%u  Tolerance:%u ms"
			 "  Window:%u packets\n",
		    l_ptr->name, status, l_ptr->max_pkt, 
		    l_ptr->priority, l_ptr->tolerance, l_ptr->queue_limit[0]);
	tipc_printf(&pb, "  RX packets:%u fragments:%u/%u bundles:%u/%u\n",
		    l_ptr->next_in_no - l_ptr->stats.recv_info,
		    l_ptr->stats.recv_fragments,
		    l_ptr->stats.recv_fragmented,
		    l_ptr->stats.recv_bundles,
		    l_ptr->stats.recv_bundled);
	tipc_printf(&pb, "  TX packets:%u fragments:%u/%u bundles:%u/%u\n",
		    l_ptr->next_out_no - l_ptr->stats.sent_info,
		    l_ptr->stats.sent_fragments,
		    l_ptr->stats.sent_fragmented,
		    l_ptr->stats.sent_bundles,
		    l_ptr->stats.sent_bundled);
	profile_total = l_ptr->stats.msg_length_counts;
	if (!profile_total)
		profile_total = 1;
	tipc_printf(&pb, "  TX profile sample:%u packets  average:%u octets\n"
			 "  0-64:%u%% -256:%u%% -1024:%u%% -4096:%u%% "
			 "-16354:%u%% -32768:%u%% -66000:%u%%\n",
		    l_ptr->stats.msg_length_counts,
		    l_ptr->stats.msg_lengths_total / profile_total,
		    percent(l_ptr->stats.msg_length_profile[0], profile_total),
		    percent(l_ptr->stats.msg_length_profile[1], profile_total),
		    percent(l_ptr->stats.msg_length_profile[2], profile_total),
		    percent(l_ptr->stats.msg_length_profile[3], profile_total),
		    percent(l_ptr->stats.msg_length_profile[4], profile_total),
		    percent(l_ptr->stats.msg_length_profile[5], profile_total),
		    percent(l_ptr->stats.msg_length_profile[6], profile_total));
	tipc_printf(&pb, "  RX states:%u probes:%u naks:%u defs:%u dups:%u\n",
		    l_ptr->stats.recv_states,
		    l_ptr->stats.recv_probes,
		    l_ptr->stats.recv_nacks,
		    l_ptr->stats.deferred_recv,
		    l_ptr->stats.duplicates);
	tipc_printf(&pb, "  TX states:%u probes:%u naks:%u acks:%u dups:%u\n",
		    l_ptr->stats.sent_states,
		    l_ptr->stats.sent_probes,
		    l_ptr->stats.sent_nacks,
		    l_ptr->stats.sent_acks,
		    l_ptr->stats.retransmitted);
	tipc_printf(&pb, "  Congestion bearer:%u link:%u  Send queue max:%u avg:%u\n",
		    l_ptr->stats.bearer_congs,
		    l_ptr->stats.link_congs,
		    l_ptr->stats.max_queue_sz,
		    l_ptr->stats.queue_sz_counts
		    ? (l_ptr->stats.accu_queue_sz / l_ptr->stats.queue_sz_counts)
		    : 0);

	tipc_node_unlock(node);
	read_unlock_bh(&tipc_net_lock);
	return tipc_printbuf_validate(&pb);
}

#define MAX_LINK_STATS_INFO 2000

struct sk_buff *tipc_link_cmd_show_stats(const void *req_tlv_area, int req_tlv_space)
{
	struct sk_buff *buf;
	struct tlv_desc *rep_tlv;
	int str_len;

	if (!TLV_CHECK(req_tlv_area, req_tlv_space, TIPC_TLV_LINK_NAME))
		return tipc_cfg_reply_error_string(TIPC_CFG_TLV_ERROR);

	buf = tipc_cfg_reply_alloc(TLV_SPACE(MAX_LINK_STATS_INFO));
	if (!buf)
		return NULL;

	rep_tlv = (struct tlv_desc *)buf->data;

	str_len = tipc_link_stats((char *)TLV_DATA(req_tlv_area),
				  (char *)TLV_DATA(rep_tlv), MAX_LINK_STATS_INFO);
	if (!str_len) {
		buf_discard(buf);
		return tipc_cfg_reply_error_string("link not found");
	}

	skb_put(buf, TLV_SPACE(str_len));
	TLV_SET(rep_tlv, TIPC_TLV_ULTRA_STRING, NULL, str_len);

	return buf;
}

#endif

#if 0
int link_control(const char *name, u32 op, u32 val)
{
	int res = -EINVAL;
	struct link *l_ptr;
	u32 bearer_id;
	struct tipc_node *node;
	u32 a;

	a = link_name2addr(name, &bearer_id);
	read_lock_bh(&tipc_net_lock);
	node = tipc_net_find_node(a);

	if (node) {
		tipc_node_lock(node);
		l_ptr = node->links[bearer_id];
		if (l_ptr) {
			if (op == TIPC_REMOVE_LINK) {
				struct bearer *b_ptr = l_ptr->b_ptr;
				spin_lock_bh(&b_ptr->publ.lock);
				tipc_link_delete(l_ptr);
				spin_unlock_bh(&b_ptr->publ.lock);
			}
			if (op == TIPC_CMD_BLOCK_LINK) {
				tipc_link_reset(l_ptr);
				l_ptr->blocked = 1;
			}
			if (op == TIPC_CMD_UNBLOCK_LINK) {
				l_ptr->blocked = 0;
			}
			res = 0;
		}
		tipc_node_unlock(node);
	}
	read_unlock_bh(&tipc_net_lock);
	return res;
}
#endif

/**
 * tipc_link_get_max_pkt - get maximum packet size to use when sending to destination
 * @dest: network address of destination node
 * @selector: used to select from set of active links
 *
 * If no active link can be found, uses default maximum packet size.
 */

u32 tipc_link_get_max_pkt(u32 dest, u32 selector)
{
	struct tipc_node *n_ptr;
	struct link *l_ptr;
	u32 res = MAX_PKT_DEFAULT;

	if (dest == tipc_own_addr)
		return MAX_MSG_SIZE;

	read_lock_bh(&tipc_net_lock);
	n_ptr = tipc_net_select_node(dest);
	if (n_ptr) {
		tipc_node_lock(n_ptr);
		l_ptr = n_ptr->active_links[selector & 1];
		if (l_ptr)
			res = l_ptr->max_pkt;
		tipc_node_unlock(n_ptr);
	}
	read_unlock_bh(&tipc_net_lock);
	return res;
}

#if 0
static void link_dump_rec_queue(struct link *l_ptr)
{
	struct sk_buff *crs;

	if (!l_ptr->oldest_deferred_in) {
		info("Reception queue empty\n");
		return;
	}
	info("Contents of Reception queue:\n");
	crs = l_ptr->oldest_deferred_in;
	while (crs) {
		if (crs->data == (void *)0x0000a3a3) {
			info("buffer %x invalid\n", crs);
			return;
		}
		msg_dbg(buf_msg(crs), "In rec queue: \n");
		crs = crs->next;
	}
}
#endif

#ifdef CONFIG_TIPC_DEBUG

static void link_dump_send_queue(struct link *l_ptr)
{
	if (l_ptr->next_out) {
		info("\nContents of unsent queue:\n");
		dbg_print_buf_chain(l_ptr->next_out);
	}
	info("\nContents of send queue:\n");
	if (l_ptr->first_out) {
		dbg_print_buf_chain(l_ptr->first_out);
	}
	info("Empty send queue\n");
}

static void dbg_print_link_state(struct print_buf *buf, struct link *l_ptr)
{
	if (link_reset_reset(l_ptr) || link_reset_unknown(l_ptr)) {
		tipc_printf(buf, "Link already reset\n");
		return;
	}

	tipc_printf(buf, "Link %x<%s>:", l_ptr->addr, l_ptr->b_ptr->publ.name);
	tipc_printf(buf, ": NXO(%u):", mod(l_ptr->next_out_no));
	tipc_printf(buf, "NXI(%u):", mod(l_ptr->next_in_no));
	tipc_printf(buf, "SQUE");
	if (l_ptr->first_out) {
		tipc_printf(buf, "[%u..", buf_seqno(l_ptr->first_out));
		if (l_ptr->next_out)
			tipc_printf(buf, "%u..", buf_seqno(l_ptr->next_out));
		tipc_printf(buf, "%u]", buf_seqno(l_ptr->last_out));
		if ((mod(buf_seqno(l_ptr->last_out) -
			 buf_seqno(l_ptr->first_out))
		     != (l_ptr->out_queue_size - 1))
		    || (l_ptr->last_out->next != 0)) {
			tipc_printf(buf, "\nSend queue inconsistency\n");
			tipc_printf(buf, "first_out= %x ", l_ptr->first_out);
			tipc_printf(buf, "next_out= %x ", l_ptr->next_out);
			tipc_printf(buf, "last_out= %x ", l_ptr->last_out);
			link_dump_send_queue(l_ptr);
		}
	} else
		tipc_printf(buf, "[]");
	tipc_printf(buf, "SQSIZ(%u)", l_ptr->out_queue_size);
	if (l_ptr->oldest_deferred_in) {
		u32 o = buf_seqno(l_ptr->oldest_deferred_in);
		u32 n = buf_seqno(l_ptr->newest_deferred_in);
		tipc_printf(buf, ":RQUE[%u..%u]", o, n);
		if (l_ptr->deferred_inqueue_sz != mod((n + 1) - o)) {
			tipc_printf(buf, ":RQSIZ(%u)",
				    l_ptr->deferred_inqueue_sz);
		}
	}
	if (link_working_unknown(l_ptr))
		tipc_printf(buf, ":WU");
	if (link_reset_reset(l_ptr))
		tipc_printf(buf, ":RR");
	if (link_reset_unknown(l_ptr))
		tipc_printf(buf, ":RU");
	if (link_working_working(l_ptr))
		tipc_printf(buf, ":WW");
	tipc_printf(buf, "\n");
}

static void dbg_print_link(struct link *l_ptr, const char *str)
{
	if (DBG_OUTPUT != TIPC_NULL) {
		tipc_printf(DBG_OUTPUT, str);
		dbg_print_link_state(DBG_OUTPUT, l_ptr);
	}
}

static void dbg_print_buf_chain(struct sk_buff *root_buf)
{
	if (DBG_OUTPUT != TIPC_NULL) {
		struct sk_buff *buf = root_buf;

		while (buf) {
			msg_dbg(buf_msg(buf), "In chain: ");
			buf = buf->next;
		}
	}
}

#endif
