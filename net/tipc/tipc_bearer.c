/*
 * net/tipc/tipc_bearer.c: TIPC bearer code
 *
 * Copyright (c) 1996-2006, Ericsson AB
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
#include "tipc_cfgsrv.h"
#include "tipc_dbg.h"
#include "tipc_bearer.h"
#include "tipc_link.h"
#include "tipc_port.h"
#include "tipc_discover.h"
#include "tipc_bcast.h"

#define TIPC_MAX_ADDR_STR 32

#define MAX_MEDIA 4

static struct tipc_media *media_list[MAX_MEDIA];
static u32 media_count = 0;

struct bearer *tipc_bearers = NULL;

/**
 * media_name_valid - validate media name
 *
 * Returns 1 if media name is valid, otherwise 0.
 */

static int media_name_valid(const char *name)
{
	u32 len;

	len = strlen(name);
	if ((len + 1) > TIPC_MAX_MEDIA_NAME)
		return 0;
	return (strspn(name, tipc_alphabet) == len);
}

/**
 * tipc_media_find_name - locates specified media object by name
 */

struct tipc_media *tipc_media_find_name(const char *name)
{
	u32 i;

	for (i = 0; i < media_count; i++) {
		if (!strcmp(media_list[i]->name, name))
			return media_list[i];
	}
	return NULL;
}

/**
 * media_find_id - locates specified media object by media identifier
 */

static struct tipc_media *media_find_id(u8 type)
{
	u32 i;

	for (i = 0; i < media_count; i++) {
		if (media_list[i]->media_id == type)
			return media_list[i];
	}
	return NULL;
}


/**
 * tipc_register_media - register a media type
 *
 * Bearers for this media type must be activated separately at a later stage.
 */

int  tipc_register_media(struct tipc_media *m_ptr)
{
	int res = -EINVAL;

	write_lock_bh(&tipc_net_lock);

	if (m_ptr->media_id == TIPC_MEDIA_ID_INVALID) {
		goto exit;
	}
	if (!media_name_valid(m_ptr->name)) {
		goto exit;
	}
	if ((m_ptr->priority < TIPC_MIN_LINK_PRI) &&
	    (m_ptr->priority > TIPC_MAX_LINK_PRI)) {
		goto exit;
	}
	if ((m_ptr->tolerance < TIPC_MIN_LINK_TOL) || 
	    (m_ptr->tolerance > TIPC_MAX_LINK_TOL)) {
		goto exit;
	}
	if ((m_ptr->bcast_addr.media_id != m_ptr->media_id) ||
	    (m_ptr->bcast_addr.broadcast == 0)) {
		goto exit;
	}
	if (!m_ptr->send_msg || 
	    !m_ptr->enable_bearer || !m_ptr->disable_bearer ||
	    !m_ptr->addr2str || !m_ptr->str2addr ||
	    !m_ptr->addr2msg || !m_ptr->msg2addr) {
		goto exit;
	}

	if (media_count >= MAX_MEDIA) {
		goto exit;
	}
	if (media_find_id(m_ptr->media_id) || tipc_media_find_name(m_ptr->name)) {
		goto exit;
	}

	media_list[media_count++] = m_ptr;
	res = 0;
exit:
	write_unlock_bh(&tipc_net_lock);
	if (res)
		warn("Media <%s> rejected\n", m_ptr->name);
	else
		dbg("Media <%s> registered\n", m_ptr->name);
	return res;
}

/**
 * tipc_media_addr_printf - record media address in print buffer
 */

void tipc_media_addr_printf(struct print_buf *pb, struct tipc_media_addr *a)
{
#if defined(CONFIG_TIPC_CONFIG_SERVICE) \
    || defined(CONFIG_TIPC_SYSTEM_MSGS) \
    || defined(CONFIG_TIPC_DEBUG)

	char addr_str[TIPC_MAX_ADDR_STR];
	struct tipc_media *m_ptr;

	m_ptr = media_find_id(a->media_id);
	if ((m_ptr != NULL) && 
	    (m_ptr->addr2str(a, addr_str, sizeof(addr_str)) == 0)) {
		tipc_printf(pb, "%s(%s)", m_ptr->name, addr_str);
	} else {
		unchar *addr = (unchar *)&a->value;
		int i;

		tipc_printf(pb, "UNKNOWN(%u)", a->media_id);
		for (i = 0; i < sizeof(a->value); i++) {
			tipc_printf(pb, "-%02x", addr[i]);
		}
	}
#endif
}

#ifdef CONFIG_TIPC_CONFIG_SERVICE

/**
 * tipc_media_get_names - record names of registered media in buffer
 */

struct sk_buff *tipc_media_get_names(void)
{
	struct sk_buff *buf;
	int i;

	buf = tipc_cfg_reply_alloc(MAX_MEDIA * TLV_SPACE(TIPC_MAX_MEDIA_NAME));
	if (!buf)
		return NULL;

	read_lock_bh(&tipc_net_lock);
	for (i = 0; i < media_count; i++) {
		tipc_cfg_append_tlv(buf, TIPC_TLV_MEDIA_NAME, 
				    media_list[i]->name, 
				    strlen(media_list[i]->name) + 1);
	}
	read_unlock_bh(&tipc_net_lock);
	return buf;
}

#endif

/**
 * bearer_name_validate - validate & (optionally) deconstruct bearer name
 * @name - ptr to bearer name string
 * @name_parts - ptr to area for bearer name components (or NULL if not needed)
 *
 * Returns 1 if bearer name is valid, otherwise 0.
 */

static int bearer_name_validate(const char *name,
				struct bearer_name *name_parts)
{
	char name_copy[TIPC_MAX_BEARER_NAME];
	char *media_name;
	char *if_name;
	u32 media_len;
	u32 if_len;

	/* copy bearer name & ensure length is OK */

	name_copy[TIPC_MAX_BEARER_NAME - 1] = 0;
	/* need above in case non-Posix strncpy() doesn't pad with nulls */
	strncpy(name_copy, name, TIPC_MAX_BEARER_NAME);
	if (name_copy[TIPC_MAX_BEARER_NAME - 1] != 0)
		return 0;

	/* ensure all component parts of bearer name are present */

	media_name = name_copy;
	if ((if_name = strchr(media_name, ':')) == NULL)
		return 0;
	*(if_name++) = 0;
	media_len = if_name - media_name;
	if_len = strlen(if_name) + 1;

	/* validate component parts of bearer name */

	if ((media_len <= 1) || (media_len > TIPC_MAX_MEDIA_NAME) ||
	    (if_len <= 1) || (if_len > TIPC_MAX_IF_NAME) ||
	    (strspn(media_name, tipc_alphabet) != (media_len - 1)) ||
	    (strspn(if_name, tipc_alphabet) != (if_len - 1)))
		return 0;

	/* return bearer name components, if necessary */

	if (name_parts) {
		strcpy(name_parts->media_name, media_name);
		strcpy(name_parts->if_name, if_name);
	}
	return 1;
}

/**
 * bearer_find_interface - locates bearer object with matching interface name
 */

static struct bearer *bearer_find_interface(const char *if_name)
{
	struct bearer *b_ptr;
	char *b_if_name;
	u32 i;

	for (i = 0, b_ptr = tipc_bearers; i < TIPC_MAX_BEARERS; i++, b_ptr++) {
		if (!b_ptr->active)
			continue;
		b_if_name = strchr(b_ptr->publ.name, ':') + 1;
		if (!strcmp(b_if_name, if_name))
			return b_ptr;
	}
	return NULL;
}

/**
 * tipc_bearer_find - locates bearer object with matching bearer name or interface name
 */

struct bearer *tipc_bearer_find(const char *name)
{
	struct bearer *b_ptr;
	int i;

	if (tipc_mode != TIPC_NET_MODE)
		return NULL;

	if (strchr(name,':') == NULL)
		return bearer_find_interface(name);

	for (i = 0, b_ptr = tipc_bearers; i < TIPC_MAX_BEARERS; i++, b_ptr++) {
		if (b_ptr->active && (!strcmp(b_ptr->publ.name, name)))
			return b_ptr;
	}
	return NULL;
}

#ifdef CONFIG_TIPC_CONFIG_SERVICE

/**
 * tipc_bearer_get_names - record names of bearers in buffer
 */

struct sk_buff *tipc_bearer_get_names(void)
{
	struct sk_buff *buf;
	struct bearer *b_ptr;
	int i, j;

	buf = tipc_cfg_reply_alloc(TIPC_MAX_BEARERS * TLV_SPACE(TIPC_MAX_BEARER_NAME));
	if (!buf)
		return NULL;

	read_lock_bh(&tipc_net_lock);
	for (i = 0; i < media_count; i++) {
		for (j = 0; j < TIPC_MAX_BEARERS; j++) {
			b_ptr = &tipc_bearers[j];
			if (b_ptr->active && (b_ptr->media == media_list[i])) {
				tipc_cfg_append_tlv(buf, TIPC_TLV_BEARER_NAME, 
						    b_ptr->publ.name, 
						    strlen(b_ptr->publ.name) + 1);
			}
		}
	}
	read_unlock_bh(&tipc_net_lock);
	return buf;
}

#endif

void tipc_bearer_add_dest(struct bearer *b_ptr, u32 dest,
			  struct tipc_media_addr *maddr)
{
	struct discoverer *d_ptr;
	struct discoverer *temp_d_ptr;

	if (in_own_cluster(dest)) {
		tipc_nmap_add(&b_ptr->nodes, dest);
		tipc_bcbearer_sort();
	}

	list_for_each_entry_safe(d_ptr, temp_d_ptr, &b_ptr->disc_list, disc_list) {
		if (tipc_in_scope(d_ptr->domain, dest)) {
			d_ptr->num_nodes++;
			/* tipc_disc_update(d_ptr); */
		}
	}
}

void tipc_bearer_remove_dest(struct bearer *b_ptr, u32 dest,
			  struct tipc_media_addr *maddr)
{
	struct discoverer *d_ptr;
	struct discoverer *temp_d_ptr;

	if (in_own_cluster(dest)) {
		tipc_nmap_remove(&b_ptr->nodes, dest);
		tipc_bcbearer_sort();
	}

	list_for_each_entry_safe(d_ptr, temp_d_ptr, &b_ptr->disc_list, disc_list) {
		if (tipc_in_scope(d_ptr->domain, dest)) {
			d_ptr->num_nodes--;
			tipc_disc_update(d_ptr);
		}
	}
}


/*  
 * tipc_bearer_send_discover: 'Individual' discoverer's, i.e. those having a
 * fully specified address, are controlled by the corresponding link's timer,
 * instead of the discovery timer.
 */

void tipc_bearer_send_discover(struct bearer *b_ptr, u32 dest)
{
	/* TODO: This needs to be reworked */

	struct discoverer *d_ptr;
	struct discoverer *temp_d_ptr;

	list_for_each_entry_safe(d_ptr, temp_d_ptr, &b_ptr->disc_list, disc_list) {
		if (d_ptr->domain == dest) {
			tipc_disc_send_msg(d_ptr);
			break;
		}
	}
}

/**
 * tipc_bearer_remove_discoverer(): 
 * Remove the discovery item for 'dest' from bearer's list.
 * Note: bearer item is locked. tipc_net_lock is write_locked.
 */

void tipc_bearer_remove_discoverer(struct bearer *b_ptr, u32 dest)
{
	struct discoverer *d_ptr;
	struct discoverer *temp_d_ptr;

	if (in_own_cluster(dest))
		return;

	list_for_each_entry_safe(d_ptr, temp_d_ptr, &b_ptr->disc_list, disc_list) {
		if (tipc_in_scope(dest, d_ptr->domain)) {
			tipc_disc_deactivate(d_ptr);
			tipc_disc_delete(d_ptr);
		}
	}
}

/*
 * bearer_push(): Resolve bearer congestion. Force the waiting
 * links to push out their unsent packets, one packet per link
 * per iteration, until all packets are gone or congestion reoccurs.
 * 'tipc_net_lock' is read_locked when this function is called
 * bearer.lock must be taken before calling
 * Returns binary true(1) ore false(0)
 */
static int bearer_push(struct bearer *b_ptr)
{
	u32 res = 0;
	struct link *ln, *tln;

	if (b_ptr->publ.blocked)
		return 0;

	while (!list_empty(&b_ptr->cong_links) && (res != PUSH_FAILED)) {
		list_for_each_entry_safe(ln, tln, &b_ptr->cong_links, link_list) {
			res = tipc_link_push_packet(ln);
			if (res == PUSH_FAILED)
				break;
			if (res == PUSH_FINISHED)
				list_move_tail(&ln->link_list, &b_ptr->links);
		}
	}
	return list_empty(&b_ptr->cong_links);
}

void tipc_bearer_lock_push(struct bearer *b_ptr)
{
	int res;

	spin_lock_bh(&b_ptr->publ.lock);
	res = bearer_push(b_ptr);
	spin_unlock_bh(&b_ptr->publ.lock);
	if (res)
		tipc_bcbearer_push();
}


/*
 * Interrupt enabling new requests after bearer congestion or blocking:
 * See bearer_send().
 */
void tipc_continue(struct tipc_bearer *tb_ptr)
{
	struct bearer *b_ptr = (struct bearer *)tb_ptr;

	spin_lock_bh(&b_ptr->publ.lock);
	b_ptr->continue_count++;
	if (!list_empty(&b_ptr->cong_links))
		tipc_k_signal((Handler)tipc_bearer_lock_push, (unsigned long)b_ptr);
	b_ptr->publ.blocked = 0;
	spin_unlock_bh(&b_ptr->publ.lock);
}

/*
 * Schedule link for sending of messages after the bearer
 * has been deblocked by 'continue()'. This method is called
 * when somebody tries to send a message via this link while
 * the bearer is congested. 'tipc_net_lock' is in read_lock here
 * bearer.lock is busy
 */

static void tipc_bearer_schedule_unlocked(struct bearer *b_ptr, struct link *l_ptr)
{
	list_move_tail(&l_ptr->link_list, &b_ptr->cong_links);
}

/*
 * Schedule link for sending of messages after the bearer
 * has been deblocked by 'continue()'. This method is called
 * when somebody tries to send a message via this link while
 * the bearer is congested. 'tipc_net_lock' is in read_lock here,
 * bearer.lock is free
 */

void tipc_bearer_schedule(struct bearer *b_ptr, struct link *l_ptr)
{
	spin_lock_bh(&b_ptr->publ.lock);
	tipc_bearer_schedule_unlocked(b_ptr, l_ptr);
	spin_unlock_bh(&b_ptr->publ.lock);
}


/*
 * tipc_bearer_resolve_congestion(): Check if there is bearer congestion,
 * and if there is, try to resolve it before returning.
 * 'tipc_net_lock' is read_locked when this function is called
 */
int tipc_bearer_resolve_congestion(struct bearer *b_ptr, struct link *l_ptr)
{
	int res = 1;

	if (list_empty(&b_ptr->cong_links))
		return 1;
	spin_lock_bh(&b_ptr->publ.lock);
	if (!bearer_push(b_ptr)) {
		tipc_bearer_schedule_unlocked(b_ptr, l_ptr);
		res = 0;
	}
	spin_unlock_bh(&b_ptr->publ.lock);
	return res;
}


/**
 * tipc_bearer_congested - determines if bearer is currently congested
 */

int tipc_bearer_congested(struct bearer *b_ptr, struct link *l_ptr)
{
	if (unlikely(b_ptr->publ.blocked))
		return 1;
	if (likely(list_empty(&b_ptr->cong_links)))
		return 0;
	return !tipc_bearer_resolve_congestion(b_ptr, l_ptr);
}

/**
 * tipc_enable_bearer - enable bearer with the given name
 */

int tipc_enable_bearer(const char *name, u32 disc_domain, u32 priority)
{
	struct bearer *b_ptr;
	struct tipc_media *m_ptr;
	struct bearer_name b_name;
	char addr_string[16];
	u32 bearer_id;
	u32 with_this_prio;
	u32 i;
	int res = -EINVAL;

	if (tipc_mode != TIPC_NET_MODE) {
		warn("Bearer <%s> rejected, not supported in standalone mode\n",
		     name);
		return -ENOPROTOOPT;
	}
	if (!bearer_name_validate(name, &b_name)) {
		warn("Bearer <%s> rejected, illegal name\n", name);
		return -EINVAL;
	}
	if (!tipc_addr_domain_valid(disc_domain)) {
		warn("Bearer <%s> rejected, illegal discovery domain\n", name);
		return -EINVAL;
	}
	if ((priority < TIPC_MIN_LINK_PRI ||
	     priority > TIPC_MAX_LINK_PRI) &&
	    (priority != TIPC_MEDIA_LINK_PRI)) {
		warn("Bearer <%s> rejected, illegal priority\n", name);
		return -EINVAL;
	}

	write_lock_bh(&tipc_net_lock);

	m_ptr = tipc_media_find_name(b_name.media_name);
	if (!m_ptr) {
		warn("Bearer <%s> rejected, media <%s> not registered\n", name,
		     b_name.media_name);
		goto failed;
	}
	if (priority == TIPC_MEDIA_LINK_PRI)
		priority = m_ptr->priority;

restart:
	bearer_id = TIPC_MAX_BEARERS;
	with_this_prio = 1;
	for (i = TIPC_MAX_BEARERS; i-- != 0; ) {
		if (!tipc_bearers[i].in_use) {
			bearer_id = i;
			continue;
		}
		if (!strcmp(name, tipc_bearers[i].publ.name)) {
			warn("Bearer <%s> rejected, already enabled\n", name);
			goto failed;
		}
		if ((tipc_bearers[i].priority == priority) &&
		    (++with_this_prio > 2)) {
			if (priority-- == 0) {
				warn("Bearer <%s> rejected, duplicate priority\n",
				     name);
				goto failed;
			}
			warn("Bearer <%s> priority adjustment required %u->%u\n",
			     name, priority + 1, priority);
			goto restart;
		}
	}
	if (bearer_id >= TIPC_MAX_BEARERS) {
		warn("Bearer <%s> rejected, bearer limit reached (%u)\n", 
		     name, TIPC_MAX_BEARERS);
		goto failed;
	}

	b_ptr = &tipc_bearers[bearer_id];
	b_ptr->in_use = 1;
	strcpy(b_ptr->publ.name, name);
	b_ptr->priority = priority;

	write_unlock_bh(&tipc_net_lock);
	res = m_ptr->enable_bearer(&b_ptr->publ);
	if (res) {
		b_ptr->in_use = 0;
		warn("Bearer <%s> rejected, enable failure (%d)\n", name, -res);
		return res;
	}
	write_lock_bh(&tipc_net_lock);

	b_ptr->identity = bearer_id;
	b_ptr->media = m_ptr;
	b_ptr->tolerance = m_ptr->tolerance;
	b_ptr->window = m_ptr->window;
	b_ptr->net_plane = bearer_id + 'A';

	INIT_LIST_HEAD(&b_ptr->cong_links);
	INIT_LIST_HEAD(&b_ptr->links);
	INIT_LIST_HEAD(&b_ptr->disc_list);
	if (disc_domain != tipc_own_addr) {
		tipc_disc_create(b_ptr, &m_ptr->bcast_addr, disc_domain);
	}
	spin_lock_init(&b_ptr->publ.lock);
	b_ptr->active = 1;

	write_unlock_bh(&tipc_net_lock);

	tipc_addr_string_fill(addr_string, disc_domain);
	info("Enabled bearer <%s>, discovery domain %s, priority %u\n",
	     name, addr_string, priority);
	return 0;
failed:
	write_unlock_bh(&tipc_net_lock);
	return res;
}

/**
 * tipc_block_bearer(): Block the bearer with the given name,
 *                      and reset all its links
 */

int tipc_block_bearer(const char *name)
{
	struct bearer *b_ptr = NULL;
	struct link *l_ptr;
	struct link *temp_l_ptr;

	read_lock_bh(&tipc_net_lock);
	b_ptr = tipc_bearer_find(name);
	if (!b_ptr) {
		warn("Attempt to block unknown bearer <%s>\n", name);
		read_unlock_bh(&tipc_net_lock);
		return -EINVAL;
	}

	info("Blocking bearer <%s>\n", name);
	spin_lock_bh(&b_ptr->publ.lock);
	b_ptr->publ.blocked = 1;
	list_for_each_entry_safe(l_ptr, temp_l_ptr, &b_ptr->links, link_list) {
		struct tipc_node *n_ptr = l_ptr->owner;

		tipc_node_lock(n_ptr);
		tipc_link_reset(l_ptr);
		tipc_node_unlock(n_ptr);
	}
	spin_unlock_bh(&b_ptr->publ.lock);
	read_unlock_bh(&tipc_net_lock);
	return 0;
}

/**
 * bearer_disable -
 *
 * Note: This routine assumes caller holds tipc_net_lock.
 */

static int bearer_disable(struct bearer *b_ptr)
{
	struct link *l_ptr;
	struct link *temp_l_ptr;
	struct discoverer *d_ptr;
	struct discoverer *temp_d_ptr;

	info("Disabling bearer <%s>\n", b_ptr->publ.name);
	spin_lock_bh(&b_ptr->publ.lock);
	b_ptr->publ.blocked = 1;
	b_ptr->media->disable_bearer(&b_ptr->publ);
	list_for_each_entry_safe(l_ptr, temp_l_ptr, &b_ptr->links, link_list) {
		tipc_link_delete(l_ptr);
	}
	spin_unlock_bh(&b_ptr->publ.lock);

	/* Safe to delete discovery struct here. Bearer is inactive now */

	list_for_each_entry_safe(d_ptr, temp_d_ptr, &b_ptr->disc_list, disc_list) {
		tipc_disc_deactivate(d_ptr);
		tipc_disc_delete(d_ptr);
	}

	spin_lock_term(&b_ptr->publ.lock); 
	memset(b_ptr, 0, sizeof(struct bearer));
	return 0;
}

int tipc_disable_bearer(const char *name)
{
	struct bearer *b_ptr;
	int res;

	write_lock_bh(&tipc_net_lock);
	b_ptr = tipc_bearer_find(name);
	if (b_ptr == NULL) {
		warn("Attempt to disable unknown bearer <%s>\n", name);
		res = -EINVAL;
	}
	else {
		res = bearer_disable(b_ptr);
	}
	write_unlock_bh(&tipc_net_lock);
	return res;
}


int tipc_bearer_init(void)
{
	int res;

	write_lock_bh(&tipc_net_lock);
	tipc_bearers = kcalloc(TIPC_MAX_BEARERS, sizeof(struct bearer), GFP_ATOMIC);
	if (tipc_bearers) {
		res = 0;
	} else {
		kfree(tipc_bearers);
		tipc_bearers = NULL;
		res = -ENOMEM;
	}
	write_unlock_bh(&tipc_net_lock);
	return res;
}

void tipc_bearer_stop(void)
{
	u32 i;

	if (!tipc_bearers)
		return;

	for (i = 0; i < TIPC_MAX_BEARERS; i++) {
		if (tipc_bearers[i].active)
			bearer_disable(&tipc_bearers[i]);
	}
	kfree(tipc_bearers);
	tipc_bearers = NULL;
	media_count = 0;
}

