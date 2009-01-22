/*
 * net/tipc/tipc_name_table.c: TIPC name table code
 *
 * Copyright (c) 2000-2006, Ericsson AB
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
#include "tipc_name_table.h"
#include "tipc_name_distr.h"
#include "tipc_addr.h"
#include "tipc_net.h"
#include "tipc_topsrv.h"
#include "tipc_port.h"
#include "tipc_bcast.h"

/*
 * NAME TABLE CODE
 */

static int tipc_nametbl_size = 1024;		/* must be a power of 2 */

/**
 * struct sub_seq - container for all published instances of a name sequence
 * @lower: name sequence lower bound
 * @upper: name sequence upper bound
 * @node_list: circular list of publications made by own node
 * @cluster_list: circular list of publications made by own cluster
 * @zone_list: circular list of publications made by own zone
 * @node_list_size: number of entries in "node_list"
 * @cluster_list_size: number of entries in "cluster_list"
 * @zone_list_size: number of entries in "zone_list"
 * 
 * Note: The zone list always contains at least one entry, since all
 *       publications of the associated name sequence belong to it.
 *       (The cluster and node lists may be empty.)
 */

struct sub_seq {
	u32 lower;
	u32 upper;
	struct publication *node_list;
	struct publication *cluster_list;
	struct publication *zone_list;
	u32 node_list_size;
	u32 cluster_list_size;
	u32 zone_list_size;
};

/**
 * struct name_seq - container for all published instances of a name type
 * @type: 32 bit 'type' value for name sequence
 * @sseq: pointer to dynamically-sized array of sub-sequences of this 'type';
 *        sub-sequences are sorted in ascending order
 * @alloc: number of sub-sequences currently in array
 * @first_free: array index of first unused sub-sequence entry
 * @ns_list: links to adjacent name sequences in hash chain
 * @subscriptions: list of subscriptions for this 'type'
 * @lock: spinlock controlling access to publication lists of all sub-sequences
 */

struct name_seq {
	u32 type;
	struct sub_seq *sseqs;
	u32 alloc;
	u32 first_free;
	struct hlist_node ns_list;
	struct list_head subscriptions;
	spinlock_t lock;
};

/**
 * struct name_table - table containing all existing port name publications
 * @types: pointer to fixed-sized array of name sequence lists,
 *         accessed via hashing on 'type'; name sequence lists are *not* sorted
 * @local_publ_count: number of publications issued by this node
 */

struct name_table {
	struct hlist_head *types;
	u32 local_publ_count;
};

static struct name_table table = { NULL } ;
static atomic_t rsv_publ_ok = ATOMIC_INIT(0);
DEFINE_RWLOCK(tipc_nametbl_lock);

/*
 * distribution mask array, subscripted by scope of associated publication
 * (eg. TIPC_NODE_SCOPE); note that first array entry is unused
 */

static u32 dist_mask_for_scope[5] = {
	0,
	TIPC_DIST_TO_ZONE | TIPC_DIST_TO_CLUSTER,
	TIPC_DIST_TO_CLUSTER,
	0,
	TIPC_DIST_TO_NETWORK | TIPC_DIST_TO_ZONE | TIPC_DIST_TO_CLUSTER
	};

static int hash(int x)
{
	return(x & (tipc_nametbl_size - 1));
}

/**
 * publ_create - create a publication structure
 */

static struct publication *publ_create(u32 type, u32 lower, u32 upper,
				       u32 scope, u32 node, u32 port_ref,
				       u32 key)
{
	struct publication *publ = kzalloc(sizeof(*publ), GFP_ATOMIC);
	if (publ == NULL) {
		warn("Publication creation failure, no memory\n");
		return NULL;
	}

	publ->type = type;
	publ->lower = lower;
	publ->upper = upper;
	publ->scope = scope;
	publ->node = node;
	publ->ref = port_ref;
	publ->key = key;
	INIT_LIST_HEAD(&publ->distr_list);
	INIT_LIST_HEAD(&publ->pport_list);
	INIT_LIST_HEAD(&publ->subscr.sub_list);
	return publ;
}

/**
 * tipc_subseq_alloc - allocate a specified number of sub-sequence structures
 */

static struct sub_seq *tipc_subseq_alloc(u32 cnt)
{
	struct sub_seq *sseq = kcalloc(cnt, sizeof(struct sub_seq), GFP_ATOMIC);
	return sseq;
}

/**
 * tipc_nameseq_create - create a name sequence structure for the specified 'type'
 *
 * Allocates a single sub-sequence structure and sets it to all 0's.
 */

static struct name_seq *tipc_nameseq_create(u32 type, struct hlist_head *seq_head)
{
	struct name_seq *nseq = kzalloc(sizeof(*nseq), GFP_ATOMIC);
	struct sub_seq *sseq = tipc_subseq_alloc(1);

	if (!nseq || !sseq) {
		warn("Name sequence creation failed, no memory\n");
		kfree(nseq);
		kfree(sseq);
		return NULL;
	}

	spin_lock_init(&nseq->lock);
	nseq->type = type;
	nseq->sseqs = sseq;
	dbg("tipc_nameseq_create(): nseq = %p, type %u, ssseqs %p, ff: %u\n",
	    nseq, type, nseq->sseqs, nseq->first_free);
	nseq->alloc = 1;
	INIT_LIST_HEAD(&nseq->subscriptions);
	hlist_add_head(&nseq->ns_list, seq_head);
	return nseq;
}

/**
 * nameseq_delete_check - deletes a name sequence structure if now unused
 */

static void nameseq_delete_check(struct name_seq *seq)
{
	if ((seq->first_free == 0) && list_empty(&seq->subscriptions)) {
		hlist_del_init(&seq->ns_list);
		kfree(seq->sseqs);
		spin_lock_term(&seq->lock);
		kfree(seq);
	}
}

/**
 * nameseq_find_subseq - find sub-sequence (if any) matching a name instance
 *
 * Very time-critical, so binary searches through sub-sequence array.
 */

static struct sub_seq *nameseq_find_subseq(struct name_seq *nseq,
					   u32 instance)
{
	struct sub_seq *sseqs = nseq->sseqs;
	int low = 0;
	int high = nseq->first_free - 1;
	int mid;

	while (low <= high) {
		mid = (low + high) / 2;
		if (instance < sseqs[mid].lower)
			high = mid - 1;
		else if (instance > sseqs[mid].upper)
			low = mid + 1;
		else
			return &sseqs[mid];
	}
	return NULL;
}

/**
 * nameseq_locate_subseq - determine position of name instance in sub-sequence
 *
 * Returns index in sub-sequence array of the entry that contains the specified
 * instance value; if no entry contains that value, returns the position
 * where a new entry for it would be inserted in the array.
 *
 * Note: Similar to binary search code for locating a sub-sequence.
 */

static u32 nameseq_locate_subseq(struct name_seq *nseq, u32 instance)
{
	struct sub_seq *sseqs = nseq->sseqs;
	int low = 0;
	int high = nseq->first_free - 1;
	int mid;

	while (low <= high) {
		mid = (low + high) / 2;
		if (instance < sseqs[mid].lower)
			high = mid - 1;
		else if (instance > sseqs[mid].upper)
			low = mid + 1;
		else
			return mid;
	}
	return low;
}

/**
 * tipc_nameseq_insert_publ -
 */

struct publication *tipc_nameseq_insert_publ(struct name_seq *nseq,
					     u32 type, u32 lower, u32 upper,
					     u32 scope, u32 node, u32 port, u32 key)
{
	struct subscription *s;
	struct subscription *st;
	struct publication *publ;
	struct sub_seq *sseq;
	int created_subseq = 0;

	sseq = nameseq_find_subseq(nseq, lower);
	dbg("nameseq_ins: for seq %p, {%u,%u}, found sseq %p\n",
	    nseq, type, lower, sseq);
	if (sseq) {

		/* Lower end overlaps existing entry => need an exact match */

		if ((sseq->lower != lower) || (sseq->upper != upper)) {
			warn("Cannot publish {%u,%u,%u}, overlap error\n",
			     type, lower, upper);
			return NULL;
		}
	} else {
		u32 inspos;
		struct sub_seq *freesseq;

		/* Find where lower end should be inserted */

		inspos = nameseq_locate_subseq(nseq, lower);

		/* Fail if upper end overlaps into an existing entry */

		if ((inspos < nseq->first_free) &&
		    (upper >= nseq->sseqs[inspos].lower)) {
			warn("Cannot publish {%u,%u,%u}, overlap error\n",
			     type, lower, upper);
			return NULL;
		}

		/* Ensure there is space for new sub-sequence */

		if (nseq->first_free == nseq->alloc) {
			struct sub_seq *sseqs = tipc_subseq_alloc(nseq->alloc * 2);

			if (!sseqs) {
				warn("Cannot publish {%u,%u,%u}, no memory\n",
				     type, lower, upper);
				return NULL;
			}
			dbg("Allocated %u more sseqs\n", nseq->alloc);
			memcpy(sseqs, nseq->sseqs,
			       nseq->alloc * sizeof(struct sub_seq));
			kfree(nseq->sseqs);
			nseq->sseqs = sseqs;
			nseq->alloc *= 2;
		}
		dbg("Have %u sseqs for type %u\n", nseq->alloc, type);

		/* Insert new sub-sequence */

		dbg("ins in pos %u, ff = %u\n", inspos, nseq->first_free);
		sseq = &nseq->sseqs[inspos];
		freesseq = &nseq->sseqs[nseq->first_free];
		memmove(sseq + 1, sseq, ((char *)freesseq - (char *)sseq));
		memset(sseq, 0, sizeof (*sseq));
		nseq->first_free++;
		sseq->lower = lower;
		sseq->upper = upper;
		created_subseq = 1;
	}
	dbg("inserting {%u,%u,%u} from <0x%x:%u> into sseq %p(%u,%u) of seq %p\n",
	    type, lower, upper, node, port, sseq,
	    sseq->lower, sseq->upper, nseq);

	/* Check if there already is an identical publication : */

	publ = sseq->zone_list;
	if (publ != NULL) do {

		if ((publ->key == key) && (publ->ref == port) &&
		    ((publ->node == node) || !publ->node))
			return NULL;

		publ = publ->zone_list_next;

	} while (publ != sseq->zone_list);

	/* Insert a publication: */

	publ = publ_create(type, lower, upper, scope, node, port, key);
	if (!publ)
		return NULL;

	sseq->zone_list_size++;
	if (!sseq->zone_list)
		sseq->zone_list = publ->zone_list_next = publ;
	else {
		publ->zone_list_next = sseq->zone_list->zone_list_next;
		sseq->zone_list->zone_list_next = publ;
	}

	if (addr_in_cluster(node)) {
		sseq->cluster_list_size++;
		if (!sseq->cluster_list)
			sseq->cluster_list = publ->cluster_list_next = publ;
		else {
			publ->cluster_list_next =
			sseq->cluster_list->cluster_list_next;
			sseq->cluster_list->cluster_list_next = publ;
		}
	}

	if (addr_in_node(node)) {
		sseq->node_list_size++;
		if (!sseq->node_list)
			sseq->node_list = publ->node_list_next = publ;
		else {
			publ->node_list_next = sseq->node_list->node_list_next;
			sseq->node_list->node_list_next = publ;
		}
	}

	/*
	 * Any subscriptions waiting for notification?
	 */
	list_for_each_entry_safe(s, st, &nseq->subscriptions, nameseq_list) {
		tipc_subscr_report_overlap(s,
					   publ->lower,
					   publ->upper,
					   TIPC_PUBLISHED,
					   publ->ref,
					   publ->node,
					   created_subseq);
	}
	return publ;
}

/**
 * tipc_nameseq_remove_publ -
 *
 * NOTE: There may be cases where TIPC is asked to remove a publication
 * that is not in the name table.  For example, if another node issues a
 * publication for a name sequence that overlaps an existing name sequence
 * the publication will not be recorded, which means the publication won't
 * be found when the name sequence is later withdrawn by that node.
 * A failed withdraw request simply returns a failure indication and lets the
 * caller issue any error or warning messages associated with such a problem.
 */

struct publication *tipc_nameseq_remove_publ(struct name_seq *nseq, u32 inst,
					     u32 node, u32 ref, u32 key)
{
	struct publication *publ;
	struct publication *curr;
	struct publication *prev;
	struct sub_seq *sseq;
	struct sub_seq *free;
	struct subscription *s, *st;
	int removed_subseq = 0;

	sseq = nameseq_find_subseq(nseq, inst);
	if (!sseq)
		return NULL;

	dbg("tipc_nameseq_remove_publ: seq: %p, sseq %p, {%u,%u}, key %u\n",
	    nseq, sseq, nseq->type, inst, key);

	/* Remove publication from zone scope list */

	prev = sseq->zone_list;
	if (prev == NULL)
		return NULL;

	publ = sseq->zone_list->zone_list_next;
	while ((publ->key != key) || (publ->ref != ref) ||
	       (publ->node && (publ->node != node))) {
		prev = publ;
		publ = publ->zone_list_next;
		if (prev == sseq->zone_list) {

			/* Prevent endless loop if publication not found */

			return NULL;
		}
	}
	if (publ != sseq->zone_list)
		prev->zone_list_next = publ->zone_list_next;
	else if (publ->zone_list_next != publ) {
		prev->zone_list_next = publ->zone_list_next;
		sseq->zone_list = publ->zone_list_next;
	} else {
		sseq->zone_list = NULL;
	}
	sseq->zone_list_size--;

	/* Remove publication from cluster scope list, if present */

	if (addr_in_cluster(node)) {
		prev = sseq->cluster_list;
		curr = sseq->cluster_list->cluster_list_next;
		while (curr != publ) {
			prev = curr;
			curr = curr->cluster_list_next;
			if (prev == sseq->cluster_list) {

				/* Prevent endless loop for malformed list */

				err("Unable to de-list cluster publication\n"
				    "{%u%u}, node=0x%x, ref=%u, key=%u)\n",
				    publ->type, publ->lower, publ->node,
				    publ->ref, publ->key);
				goto end_cluster;
			}
		}
		if (publ != sseq->cluster_list)
			prev->cluster_list_next = publ->cluster_list_next;
		else if (publ->cluster_list_next != publ) {
			prev->cluster_list_next = publ->cluster_list_next;
			sseq->cluster_list = publ->cluster_list_next;
		} else {
			sseq->cluster_list = NULL;
		}
		sseq->cluster_list_size--;
	}
end_cluster:

	/* Remove publication from node scope list, if present */

	if (addr_in_node(node)) {
		prev = sseq->node_list;
		curr = sseq->node_list->node_list_next;
		while (curr != publ) {
			prev = curr;
			curr = curr->node_list_next;
			if (prev == sseq->node_list) {

				/* Prevent endless loop for malformed list */

				err("Unable to de-list node publication\n"
				    "{%u%u}, node=0x%x, ref=%u, key=%u)\n",
				    publ->type, publ->lower, publ->node,
				    publ->ref, publ->key);
				goto end_node;
			}
		}
		if (publ != sseq->node_list)
			prev->node_list_next = publ->node_list_next;
		else if (publ->node_list_next != publ) {
			prev->node_list_next = publ->node_list_next;
			sseq->node_list = publ->node_list_next;
		} else {
			sseq->node_list = NULL;
		}
		sseq->node_list_size--;
	}
end_node:

	/* Contract subseq list if no more publications for that subseq */

	if (!sseq->zone_list) {
		free = &nseq->sseqs[nseq->first_free--];
		memmove(sseq, sseq + 1, ((char *)free - (char *)(sseq + 1)));
		removed_subseq = 1;
	}

	/* Notify any waiting subscriptions */

	list_for_each_entry_safe(s, st, &nseq->subscriptions, nameseq_list) {
		tipc_subscr_report_overlap(s,
					   publ->lower,
					   publ->upper,
					   TIPC_WITHDRAWN,
					   publ->ref,
					   publ->node,
					   removed_subseq);
	}

	return publ;
}

/**
 * nameseq_subscribe: attach a subscription, and issue
 * the prescribed number of events if there is any sub-
 * sequence overlapping with the requested sequence
 */

static void nameseq_subscribe(struct name_seq *nseq, struct subscription *s)
{
	struct sub_seq *sseq = nseq->sseqs;

	list_add(&s->nameseq_list, &nseq->subscriptions);

	if (!sseq)
		return;

	while (sseq != &nseq->sseqs[nseq->first_free]) {
		struct publication *zl = sseq->zone_list;
		if (zl && tipc_subscr_overlap(s,sseq->lower,sseq->upper)) {
			struct publication *crs = zl;
			int must_report = 1;

			do {
				tipc_subscr_report_overlap(s,
							   sseq->lower,
							   sseq->upper,
							   TIPC_PUBLISHED,
							   crs->ref,
							   crs->node,
							   must_report);
				must_report = 0;
				crs = crs->zone_list_next;
			} while (crs != zl);
		}
		sseq++;
	}
}

static struct name_seq *nametbl_find_seq(u32 type)
{
	struct hlist_head *seq_head;
	struct hlist_node *seq_node;
	struct name_seq *ns;

	dbg("find_seq %u,(%u,0x%x) table = %p, hash[type] = %u\n",
	    type, ntohl(type), type, table.types, hash(type));

	seq_head = &table.types[hash(type)];
	hlist_for_each_entry(ns, seq_node, seq_head, ns_list) {
		if (ns->type == type) {
			dbg("found %p\n", ns);
			return ns;
		}
	}

	return NULL;
};

struct publication *tipc_nametbl_insert_publ(u32 type, u32 lower, u32 upper,
					     u32 scope, u32 node, u32 port, 
					     u32 key)
{
	struct name_seq *seq = nametbl_find_seq(type);

	dbg("tipc_nametbl_insert_publ: {%u,%u,%u} found %p\n", type, lower, upper, seq);
	if (lower > upper) {
		warn("Failed to publish illegal {%u,%u,%u}\n",
		     type, lower, upper);
		return NULL;
	}

	dbg("Publishing {%u,%u,%u} from 0x%x\n", type, lower, upper, node);
	if (!seq) {
		seq = tipc_nameseq_create(type, &table.types[hash(type)]);
		dbg("tipc_nametbl_insert_publ: created %p\n", seq);
	}
	if (!seq)
		return NULL;

	return tipc_nameseq_insert_publ(seq, type, lower, upper,
					scope, node, port, key);
}

struct publication *tipc_nametbl_remove_publ(u32 type, u32 lower,
					     u32 node, u32 ref, u32 key)
{
	struct publication *publ;
	struct name_seq *seq = nametbl_find_seq(type);

	if (!seq)
		return NULL;

	dbg("Withdrawing {%u,%u} from 0x%x\n", type, lower, node);
	publ = tipc_nameseq_remove_publ(seq, lower, node, ref, key);
	nameseq_delete_check(seq);
	return publ;
}

/**
 * tipc_nametbl_translate - perform name translation
 *
 * On entry, 'destnode' is the search domain used during translation.
 *
 * On exit:
 * - if name translation is deferred to another node/cluster/zone,
 *   leaves 'destnode' unchanged (will be non-zero) and returns 0
 * - if name translation is attempted and succeeds, sets 'destnode'
 *   to publishing node and returns port reference (will be non-zero)
 * - if name translation is attempted and fails, sets 'destnode' to 0
 *   and returns 0
 */

u32 tipc_nametbl_translate(u32 type, u32 instance, u32 *destnode)
{
	struct sub_seq *sseq;
	struct publication *publ;
	struct name_seq *seq;
	u32 ref;

	if (!tipc_in_scope(*destnode, tipc_own_addr))
		return 0;

	read_lock_bh(&tipc_nametbl_lock);
	seq = nametbl_find_seq(type);
	if (unlikely(!seq))
		goto not_found;
	sseq = nameseq_find_subseq(seq, instance);
	if (unlikely(!sseq))
		goto not_found;
	spin_lock_bh(&seq->lock);

	/* Closest-First Algorithm */

	if (likely(*destnode == 0)) {
		publ = sseq->node_list;
		if (publ) {
			sseq->node_list = publ->node_list_next;
found:
			ref = publ->ref;
			*destnode = publ->node;
			spin_unlock_bh(&seq->lock);
			read_unlock_bh(&tipc_nametbl_lock);
			return ref;
		}
		publ = sseq->cluster_list;
		if (publ) {
			sseq->cluster_list = publ->cluster_list_next;
			goto found;
		}
		publ = sseq->zone_list;
		sseq->zone_list = publ->zone_list_next;
		goto found;
	}

	/* Round-Robin Algorithm */

	else if (*destnode == tipc_own_addr) {
		publ = sseq->node_list;
		if (publ) {
			sseq->node_list = publ->node_list_next;
			goto found;
		}
	} else if (in_own_cluster(*destnode)) {
		publ = sseq->cluster_list;
		if (publ) {
			sseq->cluster_list = publ->cluster_list_next;
			goto found;
		}
	} else {
		publ = sseq->zone_list;
		sseq->zone_list = publ->zone_list_next;
		goto found;
	}
	spin_unlock_bh(&seq->lock);
not_found:
	read_unlock_bh(&tipc_nametbl_lock);
	*destnode = 0;
	return 0;
}

/**
 * tipc_nametbl_mc_translate - find multicast destinations
 *
 * Creates list of all local ports that overlap the given multicast address;
 * also determines if any off-node ports overlap.
 *
 * Note: Publications with a scope narrower than 'limit' are ignored.
 * (i.e. local node-scope publications mustn't receive messages arriving
 * from another node, even if the multcast link brought it here)
 *
 * Returns non-zero if any off-node ports overlap
 */

int tipc_nametbl_mc_translate(u32 type, u32 lower, u32 upper, u32 limit,
			      struct port_list *dports)
{
	struct name_seq *seq;
	struct sub_seq *sseq;
	struct sub_seq *sseq_stop;
	int res = 0;

	read_lock_bh(&tipc_nametbl_lock);
	seq = nametbl_find_seq(type);
	if (!seq)
		goto exit;

	spin_lock_bh(&seq->lock);

	sseq = seq->sseqs + nameseq_locate_subseq(seq, lower);
	sseq_stop = seq->sseqs + seq->first_free;
	for (; sseq != sseq_stop; sseq++) {
		struct publication *publ;

		if (sseq->lower > upper)
			break;

		publ = sseq->node_list;
		if (publ) {
			do {
				if (publ->scope <= limit)
					tipc_port_list_add(dports, publ->ref);
				publ = publ->node_list_next;
			} while (publ != sseq->node_list);
		}

		if (sseq->cluster_list_size != sseq->node_list_size)
			res = 1;
	}

	spin_unlock_bh(&seq->lock);
exit:
	read_unlock_bh(&tipc_nametbl_lock);
	return res;
}

/**
 * tipc_publish_rsv - publish port name using a reserved name type
 */

int tipc_publish_rsv(u32 ref, unsigned int scope, 
		     struct tipc_name_seq const *seq)
{
	int res;

	atomic_inc(&rsv_publ_ok);
	res = tipc_publish(ref, scope, seq);
	atomic_dec(&rsv_publ_ok);
	return res;
}


/**
 * tipc_nametbl_publish - add name publication to network name tables, 
 *                        but first check permissions
 */

struct publication *tipc_nametbl_publish(u32 type, u32 lower, u32 upper, 
					 u32 scope, u32 port_ref, u32 key)
{
	if ((type < TIPC_RESERVED_TYPES) && !atomic_read(&rsv_publ_ok)) {
		warn("Failed to publish reserved name <%u,%u,%u>\n",
		     type, lower, upper);
		return NULL;
	}
	return tipc_nametbl_publish_rsv(type, lower, upper, scope, port_ref, key);
}

/**
 * tipc_nametbl_publish_rsv - add name publication to network name tables,
 *                            without checking for permissions
 */

struct publication *tipc_nametbl_publish_rsv(u32 type, u32 lower, u32 upper, 
					     u32 scope, u32 port_ref, u32 key)
{
	struct publication *publ;

	if (table.local_publ_count >= tipc_max_publications) {
		warn("Publication failed, local publication limit reached (%u)\n", 
		     tipc_max_publications);
		return NULL;
	}

	write_lock_bh(&tipc_nametbl_lock);
	publ = tipc_nametbl_insert_publ(type, lower, upper, scope,
					tipc_own_addr, port_ref, key);
	if (likely(publ)) {
		table.local_publ_count++;
		tipc_named_insert_publ(publ);
	}
	write_unlock_bh(&tipc_nametbl_lock);

	if (likely(publ)) {
		tipc_named_distribute(publ, DIST_PUBLISH,
				      dist_mask_for_scope[publ->scope]);
	}
	return publ;
}

/**
 * tipc_nametbl_withdraw - withdraw name publication from network name tables
 */

void tipc_nametbl_withdraw(u32 type, u32 lower, u32 ref, u32 key)
{
	struct publication *publ;

	write_lock_bh(&tipc_nametbl_lock);
	publ = tipc_nametbl_remove_publ(type, lower, tipc_own_addr, ref, key);
	if (likely(publ)) {
		table.local_publ_count--;
		tipc_named_remove_publ(publ);
	}
	write_unlock_bh(&tipc_nametbl_lock);

	if (likely(publ)) {
		list_del_init(&publ->pport_list);
		tipc_named_distribute(publ, DIST_WITHDRAW,
				      dist_mask_for_scope[publ->scope]);
		kfree(publ);
	} else {
		err("Unable to remove local publication\n"
		    "(type=%u, lower=%u, ref=%u, key=%u)\n",
		    type, lower, ref, key);
	}
}

/**
 * tipc_nametbl_subscribe - add a subscription object to the name table
 */

void tipc_nametbl_subscribe(struct subscription *s)
{
	u32 type = s->seq.type;
	struct name_seq *seq;

	write_lock_bh(&tipc_nametbl_lock);
	seq = nametbl_find_seq(type);
	if (!seq) {
		seq = tipc_nameseq_create(type, &table.types[hash(type)]);
	}
	if (seq) {
		spin_lock_bh(&seq->lock);
		dbg_assert(seq->type == type);
		nameseq_subscribe(seq, s);
		spin_unlock_bh(&seq->lock);
	} else {
		warn("Failed to create subscription for {%u,%u,%u}\n",
		     s->seq.type, s->seq.lower, s->seq.upper);
	}
	write_unlock_bh(&tipc_nametbl_lock);
}

/**
 * tipc_nametbl_unsubscribe - remove a subscription object from name table
 */

void tipc_nametbl_unsubscribe(struct subscription *s)
{
	struct name_seq *seq;

	write_lock_bh(&tipc_nametbl_lock);
	seq = nametbl_find_seq(s->seq.type);
	if (seq != NULL) {
		spin_lock_bh(&seq->lock);
		list_del_init(&s->nameseq_list);
		spin_unlock_bh(&seq->lock);
		nameseq_delete_check(seq);
	}
	write_unlock_bh(&tipc_nametbl_lock);
}

#ifdef CONFIG_TIPC_CONFIG_SERVICE

/**
 * nametbl_sseq_list: print specified sub-sequence contents into the given buffer
 */

static void nametbl_sseq_list(struct sub_seq *sseq, struct print_buf *buf,
			      u32 depth, u32 index)
{
	static char *scope_str[] =
		{ "", " zone", " cluster", " node", " network" };

	char port_id_str[27];
	struct publication *publ = sseq->zone_list;

	tipc_printf(buf, "%-10u %-10u ", sseq->lower, sseq->upper);

	if (depth == 2 || !publ) {
		tipc_printf(buf, "\n");
		return;
	}

	do {
		sprintf(port_id_str, "<%u.%u.%u:%u>",
			tipc_zone(publ->node), tipc_cluster(publ->node),
			tipc_node(publ->node), publ->ref);
		tipc_printf(buf, "%-26s ", port_id_str);
		if (depth > 3) {
			tipc_printf(buf, "%-10u %s", publ->key, 
				    scope_str[publ->scope]);
		}

		publ = publ->zone_list_next;
		if (publ == sseq->zone_list)
			break;

		tipc_printf(buf, "\n%33s", " ");
	} while (1);

	tipc_printf(buf, "\n");
}

/**
 * nametbl_seq_list: print specified name sequence contents into the given buffer
 */

static void nametbl_seq_list(struct name_seq *seq, struct print_buf *buf,
			     u32 depth, u32 type, u32 lowbound, u32 upbound,
			     u32 index)
{
	struct sub_seq *sseq;
	char typearea[11];

	if (seq->first_free == 0)
		return;

	sprintf(typearea, "%-10u", seq->type);

	if (depth == 1) {
		tipc_printf(buf, "%s\n", typearea);
		return;
	}

	for (sseq = seq->sseqs; sseq != &seq->sseqs[seq->first_free]; sseq++) {
		if ((lowbound <= sseq->upper) && (upbound >= sseq->lower)) {
			tipc_printf(buf, "%s ", typearea);
			spin_lock_bh(&seq->lock);
			nametbl_sseq_list(sseq, buf, depth, index);
			spin_unlock_bh(&seq->lock);
			sprintf(typearea, "%10s", " ");
		}
	}
}

/**
 * nametbl_header - print name table header into the given buffer
 */

static void nametbl_header(struct print_buf *buf, u32 depth)
{
	static char *header[] = {
		"Type       ",
		"Lower      Upper      ",
		"Port Identity              ",
		"Publication Scope"
	};

	int i;

	if (depth > 4)
		depth = 4;
	for (i = 0; i < depth; i++)
		tipc_printf(buf, header[i]);
	tipc_printf(buf, "\n");
}

/**
 * nametbl_list - print specified name table contents into the given buffer
 */

static void nametbl_list(struct print_buf *buf, u32 depth_info,
			 u32 type, u32 lowbound, u32 upbound)
{
	struct hlist_head *seq_head;
	struct hlist_node *seq_node;
	struct name_seq *seq;
	int all_types;
	u32 depth;
	u32 i;

	all_types = (depth_info & TIPC_NTQ_ALLTYPES);
	depth = (depth_info & ~TIPC_NTQ_ALLTYPES);

	if (depth == 0)
		return;

	if (all_types) {
		/* display all entries in name table to specified depth */
		nametbl_header(buf, depth);
		lowbound = 0;
		upbound = ~0;
		for (i = 0; i < tipc_nametbl_size; i++) {
			seq_head = &table.types[i];
			hlist_for_each_entry(seq, seq_node, seq_head, ns_list) {
				nametbl_seq_list(seq, buf, depth, seq->type, 
						 lowbound, upbound, i);
			}
		}
	} else {
		/* display only the sequence that matches the specified type */
		if (upbound < lowbound) {
			tipc_printf(buf, "invalid name sequence specified\n");
			return;
		}
		nametbl_header(buf, depth);
		i = hash(type);
		seq_head = &table.types[i];
		hlist_for_each_entry(seq, seq_node, seq_head, ns_list) {
			if (seq->type == type) {
				nametbl_seq_list(seq, buf, depth, type, 
						 lowbound, upbound, i);
				break;
			}
		}
	}
}

#if 0
void tipc_nametbl_print(struct print_buf *buf, const char *str)
{
	tipc_printf(buf, str);
	read_lock_bh(&tipc_nametbl_lock);
	nametbl_list(buf, 0, 0, 0, 0);
	read_unlock_bh(&tipc_nametbl_lock);
}
#endif

#define MAX_NAME_TBL_QUERY 32768

struct sk_buff *tipc_nametbl_get(const void *req_tlv_area, int req_tlv_space)
{
	struct sk_buff *buf;
	struct tipc_name_table_query *argv;
	struct tlv_desc *rep_tlv;
	struct print_buf b;
	int str_len;

	if (!TLV_CHECK(req_tlv_area, req_tlv_space, TIPC_TLV_NAME_TBL_QUERY))
		return tipc_cfg_reply_error_string(TIPC_CFG_TLV_ERROR);

	buf = tipc_cfg_reply_alloc(TLV_SPACE(MAX_NAME_TBL_QUERY));
	if (!buf)
		return NULL;

	rep_tlv = (struct tlv_desc *)buf->data;
	tipc_printbuf_init(&b, TLV_DATA(rep_tlv), MAX_NAME_TBL_QUERY);
	argv = (struct tipc_name_table_query *)TLV_DATA(req_tlv_area);
	read_lock_bh(&tipc_nametbl_lock);
	nametbl_list(&b, ntohl(argv->depth), ntohl(argv->type),
		     ntohl(argv->lowbound), ntohl(argv->upbound));
	read_unlock_bh(&tipc_nametbl_lock);
	str_len = tipc_printbuf_validate(&b);

	skb_put(buf, TLV_SPACE(str_len));
	TLV_SET(rep_tlv, TIPC_TLV_ULTRA_STRING, NULL, str_len);

	return buf;
}

#if 0
void tipc_nametbl_dump(void)
{
	nametbl_list(TIPC_CONS, 0, 0, 0, 0);
}
#endif

#endif

int tipc_nametbl_init(void)
{
	table.types = kcalloc(tipc_nametbl_size, sizeof(struct hlist_head),
			      GFP_ATOMIC);
	if (!table.types)
		return -ENOMEM;

	table.local_publ_count = 0;
	return 0;
}

void tipc_nametbl_stop(void)
{
	u32 i;

	if (!table.types)
		return;

	/* Verify name table is empty, then release it */

	write_lock_bh(&tipc_nametbl_lock);
	for (i = 0; i < tipc_nametbl_size; i++) {
		if (!hlist_empty(&table.types[i]))
			err("tipc_nametbl_stop(): hash chain %u is non-null\n", i);
	}
	kfree(table.types);
	table.types = NULL;
	write_unlock_bh(&tipc_nametbl_lock);
}


/*
 * ROUTING TABLE CODE
 */

struct name_seq *route_table = NULL;
int tipc_own_routes = 0;
int tipc_all_routes = 0;

static struct subscription region_subscr;

DEFINE_RWLOCK(tipc_routetbl_lock);

/**
 * net_region_event - handle cleanup when access to a region is lost
 */

static void net_region_event(struct subscription *sub, 
			     u32 found_lower, u32 found_upper,
			     u32 event, u32 port_ref, u32 node)
{
	struct net_element *region;

	if (event == TIPC_WITHDRAWN) {

		/* 
		 * Purge name table entries/connections associated with region,
		 * if any
		 */

		region = tipc_net_lookup_element(found_lower, &tipc_regions);
		if (region != NULL) {
			net_element_lock(region);
			tipc_netsub_notify(region, found_lower);
			net_element_unlock(region);
		}

		/*
		 * Notify other zones if connectivity to another cluster
		 * in our own zone is lost 
		 */

		if (in_own_zone(found_lower)) {
			struct publication publ;

			publ.type = TIPC_ROUTE;
			publ.lower = found_lower;
			publ.upper = found_lower;
			publ.scope = TIPC_NETWORK_SCOPE;
			publ.node = tipc_own_addr;
			publ.ref = 0;
			publ.key = 0;
			tipc_route_distribute(&publ, DIST_PURGE,
					      TIPC_DIST_TO_NETWORK);
		}
	}
}

int tipc_routetbl_init(void)
{
	struct sub_seq *sseq;

	route_table = kzalloc(sizeof(struct name_seq), GFP_ATOMIC);
	sseq = tipc_subseq_alloc(1);
	if ((route_table == NULL) || (sseq == NULL)) {
		kfree(route_table);
		kfree(sseq);
		return -ENOMEM;
	}

	route_table->sseqs = sseq;
	route_table->alloc = 1;
	INIT_LIST_HEAD(&route_table->subscriptions);
	spin_lock_init(&route_table->lock);

	/* TODO: Is there a good reason why we need tipc_routetbl_lock and
	   the lock that is part of the seq entry used by the routing table? */

	region_subscr.seq.type = TIPC_ROUTE;
	region_subscr.seq.lower = tipc_addr(1, 1, 0);
	region_subscr.seq.upper = tipc_addr(255, 4095, 0);
	region_subscr.timeout = TIPC_WAIT_FOREVER;
	region_subscr.filter = TIPC_SUB_SERVICE;
	region_subscr.event_cb = net_region_event;

	nameseq_subscribe(route_table, &region_subscr);
	return 0;
}

void tipc_routetbl_stop(void)
{
	if (route_table == NULL)
		return;

	/* Verify routing table is empty, then release it */

	write_lock_bh(&tipc_routetbl_lock);
	if (route_table->first_free != 0)
		err("tipc_routetbl_stop(): routing table has %u entries\n",
		    route_table->first_free);
	kfree(route_table->sseqs);
	spin_lock_term(&route_table->lock);
	kfree(route_table);
	route_table = NULL;
	write_unlock_bh(&tipc_routetbl_lock);
}

/**
 * tipc_routetbl_translate - determine best route to out-of-cluster target
 * @target: <Z.C.N> of destination (may be a node, cluster, or zone)
 *
 * Returns <Z.C.N> of next hop in route (or 0 if unable to find a route)
 */

u32 tipc_routetbl_translate(u32 target)
{
	struct name_seq *seq;
	struct sub_seq *sseq;
	struct publication *publ;
	struct publication *publ_start;
	u32 target_region;
	u32 target_cluster;
	u32 router;
	int best_dist;
	int curr_dist;

	dbg_assert(tipc_addr_domain_valid(target));

	/* 
	 * Locate name table entry associated with target region;
	 * for a target within this node's zone, target region is its cluster,
	 * while for a target in another zone, target region is its zone
	 */

	read_lock_bh(&tipc_routetbl_lock);

	seq = route_table;

	if (likely(in_own_zone(target)))
		target_region = addr_cluster(target);
	else
		target_region = addr_zone(target);
restart:
	sseq = nameseq_find_subseq(seq, target_region);
	if (unlikely(!sseq)) {
		read_unlock_bh(&tipc_routetbl_lock);
		return 0;
	}

	/*
	 * Note: Don't need to spin_lock_bh(&seq->lock) since routes
	 * only change when tipc_routetbl_lock is write-locked
	 */

	target_cluster = addr_cluster(target);
	best_dist = 4;
	router = 0;

	/*
	 * If own node has a direct link to target region,
	 * pick the route that gets us closest to the target itself
	 */

	if (sseq->node_list) {
		publ_start = sseq->node_list;
		publ = publ_start->node_list_next;
		do {
			if (publ->ref == target) {
				router = publ->ref;
				goto found;
			} else if (addr_cluster(publ->ref) == target_cluster)
				curr_dist = 2;
			else
				curr_dist = 3;

			if (curr_dist < best_dist) {
				best_dist = curr_dist;
				router = publ->ref;
			}
			/* TODO: ADD LOAD SHARING IF curr_dist == best_dist */

			publ = publ->node_list_next;
		} while (publ != publ_start->node_list_next);
		goto found;
	}

	/*
	 * If any cluster node has a direct link to target region,
	 * pick the route that gets us closest to the target itself
	 */

	if (sseq->cluster_list) {
		publ_start = sseq->cluster_list;
		publ = publ_start->cluster_list_next;
		do {
			if (publ->ref == target)
				curr_dist = 1;
			else if (addr_cluster(publ->ref) == target_cluster)
				curr_dist = 2;
			else
				curr_dist = 3;

			if (curr_dist < best_dist) {
				best_dist = curr_dist;
				router = publ->node;
			}
			/* TODO: ADD LOAD SHARING IF curr_dist == best_dist */

			publ = publ->cluster_list_next;
		} while (publ != publ_start->cluster_list_next);
		goto found;
	}

	/*
	 * Look at all non-cluster nodes having a direct link to target region
	 * (there must be one), find the one that gets us closest to the target,
	 * then find the best route to that non-cluster node
	 */

	publ_start = sseq->zone_list;
	publ = publ_start->zone_list_next;
	do {
		if (publ->ref == target)
			curr_dist = 1;
		else if (addr_cluster(publ->ref) == target_cluster)
			curr_dist = 2;
		else
			curr_dist = 3;

		if (curr_dist < best_dist) {
			best_dist = curr_dist;
			router = publ->node;
		}
		/* TODO: ADD LOAD SHARING IF curr_dist == best_dist */

		publ = publ->zone_list_next;
	} while (publ != publ_start->zone_list_next);

	target = router;
	target_region = addr_cluster(target);
	goto restart;
	
found:
	read_unlock_bh(&tipc_routetbl_lock);
	return router;
}

/**
 * tipc_routetbl_publish - publish route to neighboring node  
 */

void tipc_routetbl_publish(unsigned long node_addr)
{
	struct publication *publ;
	u32 elm_addr;
	int scope;
	int dist_mask;

	if (in_own_zone(node_addr)) {
		elm_addr = addr_cluster(node_addr);
		scope = TIPC_CLUSTER_SCOPE;
		dist_mask = TIPC_DIST_TO_CLUSTER;
	} else {
		elm_addr = addr_zone(node_addr);
		scope = TIPC_ZONE_SCOPE;
		dist_mask = (TIPC_DIST_TO_ZONE | TIPC_DIST_TO_CLUSTER);
	}

	write_lock_bh(&tipc_routetbl_lock);
	publ = tipc_nameseq_insert_publ(route_table, TIPC_ROUTE, 
					elm_addr, elm_addr, scope,
					tipc_own_addr, node_addr, 0);
	if (likely(publ)) {
		tipc_own_routes++;
		tipc_all_routes++;
		tipc_route_insert_publ(publ);
	}
	write_unlock_bh(&tipc_routetbl_lock);

	if (likely(publ)) {
		tipc_route_distribute(publ, DIST_PUBLISH, dist_mask);
	}
}

/**
 * tipc_routetbl_withdraw - withdraw route to neighboring node  
 */

void tipc_routetbl_withdraw(unsigned long node_addr)
{
	struct publication *publ;
	u32 elm_addr;
	int dist_mask;

	if (in_own_zone(node_addr)) {
		elm_addr = addr_cluster(node_addr);
		dist_mask = TIPC_DIST_TO_CLUSTER;
	} else {
		elm_addr = addr_zone(node_addr);
		dist_mask = (TIPC_DIST_TO_CLUSTER | TIPC_DIST_TO_ZONE);
	}

	write_lock_bh(&tipc_routetbl_lock);
	publ = tipc_nameseq_remove_publ(route_table, elm_addr, tipc_own_addr,
					node_addr, 0);
	if (likely(publ)) {
		tipc_own_routes--;
		tipc_all_routes--;
		tipc_route_remove_publ(publ);
	}
	write_unlock_bh(&tipc_routetbl_lock);

	if (likely(publ)) {
		tipc_route_distribute(publ, DIST_WITHDRAW, dist_mask);
		kfree(publ);
	} else {
		err("Unable to remove local route\n"
		    "(region=0x%08x, local router=0x%08x, remote router=0x%08x)\n",
		    elm_addr, tipc_own_addr, node_addr);
	}
}

/**
 * tipc_routetbl_withdraw_node - trigger implied withdrawal
 */

void tipc_routetbl_withdraw_node(unsigned long node_addr)
{
	struct publication publ;

	publ.type = TIPC_ROUTE;
	publ.lower = node_addr;
	publ.upper = node_addr;
	publ.scope = TIPC_NETWORK_SCOPE;
	publ.node = tipc_own_addr;
	publ.ref = 0;
	publ.key = 0;
	tipc_route_distribute(&publ, DIST_PURGE,
			      (TIPC_DIST_TO_ZONE | TIPC_DIST_TO_NETWORK));
}

/**
 * tipc_routetbl_purge - notify subscribers of lost region that it is gone
 * 
 * Unlike tipc_routetbl_withdraw(), this routine does not actually remove
 * the associated routing table entry.
 */

void tipc_routetbl_purge(u32 region_addr)
{
	struct net_element *region;
	u32 elm_addr;

	if (in_own_zone(region_addr)) {
		elm_addr = addr_cluster(region_addr);
	} else {
		elm_addr = addr_zone(region_addr);
	}

	region = tipc_net_lookup_element(elm_addr, &tipc_regions);
	if (region != NULL) {
		net_element_lock(region);
		tipc_netsub_notify(region, region_addr);
		net_element_unlock(region);
	}
}

#ifdef CONFIG_TIPC_CONFIG_SERVICE

/**
 * tipc_nametbl_get_routes - return info on available routes to target
 */

struct sk_buff *tipc_nametbl_get_routes(const void *req_tlv_area,
					int req_tlv_space)
{
	u32 target;
	u32 payload_size;
	struct sk_buff *buf;
	struct sub_seq *sseq;
	struct publication *publ;
	struct publication *publ_start;
	struct tipc_route_info route_info;
	int i;

	if (!TLV_CHECK(req_tlv_area, req_tlv_space, TIPC_TLV_NET_ADDR))
		return tipc_cfg_reply_error_string(TIPC_CFG_TLV_ERROR);

	target = ntohl(*(__be32 *)TLV_DATA(req_tlv_area));
	if (!tipc_addr_domain_valid(target))
		return tipc_cfg_reply_error_string(TIPC_CFG_INVALID_VALUE
						   " (network address)");

	if (!in_own_zone(target))
		target = addr_zone(target);
	else if (!in_own_cluster(target))
		target = addr_cluster(target);
	else
		return tipc_cfg_reply_error_string(TIPC_CFG_INVALID_VALUE
			 " (network address must be outside own cluster)");

	read_lock_bh(&tipc_routetbl_lock);

	/* Allocate space for all known routes */

	payload_size = TLV_SPACE(sizeof(route_info)) * tipc_all_routes;
	if (payload_size > 32768u) {
		read_unlock_bh(&tipc_routetbl_lock);
		return tipc_cfg_reply_error_string(TIPC_CFG_NOT_SUPPORTED
						   " (too many routes)");
	}
	buf = tipc_cfg_reply_alloc(payload_size);
	if (!buf) {
		read_unlock_bh(&tipc_routetbl_lock);
		return NULL;
	}

	/* Add TLVs for each route to specified target domain */

	for (i = 0; i < route_table->first_free; i++) {
		sseq = &route_table->sseqs[i];

		if (!tipc_in_scope(target, sseq->lower))
			continue;

		/*
		 * No need to take spinlock on zone list, since the structure
		 * of the circular list can't change (only the starting point),
		 * & a change to its start is an [atomic] pointer update ...
		 */

		route_info.remote_addr = htonl(sseq->lower);
		publ_start = sseq->zone_list;
		publ = publ_start->zone_list_next;
		do {
			route_info.local_router = htonl(publ->node);
			route_info.remote_router = htonl(publ->ref);
			tipc_cfg_append_tlv(buf, TIPC_TLV_ROUTE_INFO, 
					    &route_info, sizeof(route_info));
			publ = publ->zone_list_next;
		} while (publ != publ_start->zone_list_next);
	}

	read_unlock_bh(&tipc_routetbl_lock);
	return buf;
}

#endif

