/**
 *
 *  Copyright (C) 2007 Pascal Gallard, Kerlabs <Pascal.Gallard@kerlabs.com>
 *
 */

#include <linux/skbuff.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/irqflags.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/lockdep.h>
#include <kerrighed/sys/types.h>
#include <kerrighed/krginit.h>
#include <kerrighed/krgnodemask.h>

#include <net/krgrpc/rpcid.h>
#include <net/krgrpc/rpc.h>

#include "rpc_internal.h"

/* In __rpc_send, unsure atomicity of rpc_link_seq_id and rpc_desc_set_id */
static spinlock_t lock_id;

kerrighed_node_t rpc_desc_get_client(struct rpc_desc *desc){
	BUG_ON(!desc);
	return desc->client;
}

void rpc_new_desc_id_lock(struct rpc_communicator *comm, bool lock_table)
{
	if (!irqs_disabled())
		local_bh_disable();
	spin_lock(&lock_id);
	if (lock_table)
		spin_lock(&comm->desc_clt_lock);
}

void rpc_new_desc_id_unlock(struct rpc_communicator *comm, bool unlock_table)
{
	if (unlock_table)
		spin_unlock(&comm->desc_clt_lock);
	spin_unlock(&lock_id);
	if (!irqs_disabled())
		local_bh_enable();
}

inline
int __rpc_send(struct rpc_desc* desc,
		      unsigned long seq_id, int __flags,
		      const void* data, size_t size,
		      int rpc_flags)
{
	int err = 0;

	switch (desc->type) {
	case RPC_RQ_FWD:
	case RPC_RQ_CLT:
		if (desc->desc_id == 0) {
			bool is_client = desc->type == RPC_RQ_CLT;

			BUG_ON(desc->hash_lock);

			rpc_new_desc_id_lock(desc->comm, is_client);

			desc->desc_id = desc->comm->next_desc_id++;
			if (is_client) {
				desc->client_desc_id = desc->desc_id;
				rpc_desc_table_add(desc->comm->desc_clt, desc);
				desc->hash_lock = &desc->comm->desc_clt_lock;
			}

			/* Calls rpc_new_desc_id_unlock() on success */
			err = __rpc_send_ll(desc, &desc->nodes,
					    seq_id,
					    __flags, data, size,
					    rpc_flags | RPC_FLAGS_NEW_DESC_ID);
			if (err) {
				if (is_client) {
					rpc_desc_table_remove(desc);
					desc->hash_lock = NULL;
				}
				rpc_new_desc_id_unlock(desc->comm, is_client);

				desc->desc_id = 0;
				desc->client_desc_id = 0;
			}

		} else
			err = __rpc_send_ll(desc, &desc->nodes,
					    seq_id,
					    __flags, data, size,
					    rpc_flags);
		break;

	case RPC_RQ_SRV: {
		krgnodemask_t nodes;

		krgnodes_clear(nodes);
		krgnode_set(desc->client, nodes);

		err = __rpc_send_ll(desc, &nodes, seq_id,
				    __flags, data, size,
				    rpc_flags);
		break;
	}

	default:
		printk("unexpected case %d\n", desc->type);
		BUG();
	}

	return err;
}

struct rpc_desc* rpc_begin_m(enum rpcid rpcid,
			     struct rpc_communicator *comm,
			     krgnodemask_t* nodes)
{
	struct rpc_desc* desc;
	int i;

	desc = rpc_desc_alloc();
	if(!desc)
		goto oom;

	__krgnodes_copy(&desc->nodes, nodes);
	desc->type = RPC_RQ_CLT;
	desc->client = kerrighed_node_id;
	desc->server = KERRIGHED_NODE_ID_NONE;
	
	desc->desc_send = rpc_desc_send_alloc();
	if(!desc->desc_send)
		goto oom_free_desc;

	for_each_krgnode_mask(i, desc->nodes){
		desc->desc_recv[i] = rpc_desc_recv_alloc();
		if(!desc->desc_recv[i])
			goto oom_free_desc_recv;
	}

	rpc_communicator_get(comm);
	desc->comm = comm;
	desc->conn_set = rpc_connection_set_alloc(desc->comm, &desc->nodes);
	if (IS_ERR(desc->conn_set))
		goto oom_free_desc_recv;

	desc->rpcid = rpcid;
	desc->service = rpc_services[rpcid];
	desc->client = kerrighed_node_id;

	if (__rpc_emergency_send_buf_alloc(desc, 0))
		goto oom_free_conn_set;

	desc->state = RPC_STATE_RUN;

	return desc;

oom_free_conn_set:
	rpc_connection_set_put(desc->conn_set);
oom_free_desc_recv:
	rpc_communicator_put(desc->comm);
	for_each_krgnode_mask(i, desc->nodes)
		if (desc->desc_recv[i])
			kmem_cache_free(rpc_desc_recv_cachep,
					desc->desc_recv[i]);
	kmem_cache_free(rpc_desc_send_cachep, desc->desc_send);
oom_free_desc:
	rpc_desc_put(desc);
oom:
	return NULL;
}

inline
int __rpc_end_pack(struct rpc_desc* desc)
{
	struct rpc_desc_elem *descelem, *safe;
	int err = 0;

	list_for_each_entry_safe(descelem, safe,
				 &desc->desc_send->list_desc_head,
				 list_desc_elem) {
		/*
		 * After first error, just discard remaining packets as
		 * receivers may not be able to unpack them because of the
		 * missing ones.
		 */
		if (!err && !rpc_desc_forwarded(desc)) {
			err = -EPIPE;
			if (!(desc->desc_send->flags & RPC_FLAGS_CLOSED)) {
				err = __rpc_send(desc, descelem->seq_id, 0,
						 descelem->data, descelem->size,
						 0);
				if (err)
					rpc_cancel_pack(desc);
			}
		}
		list_del(&descelem->list_desc_elem);
		kmem_cache_free(rpc_desc_elem_cachep, descelem);
	}
	return err;
}

/* TODO: do not block if cancelled */
inline
int __rpc_end_unpack(struct rpc_desc_recv* desc_recv)
{
	while (!list_empty(&desc_recv->list_provided_head)) {
		set_current_state(TASK_INTERRUPTIBLE);
		schedule();
	}
	return 0;
}

static void __rpc_end_unpack_clean_queue(struct list_head *elem_head)
{
	struct rpc_desc_elem *iter, *safe;

	list_for_each_entry_safe(iter, safe, elem_head, list_desc_elem) {
		list_del(&iter->list_desc_elem);
		rpc_desc_elem_free(iter);
	}
}

inline
int __rpc_end_unpack_clean(struct rpc_desc* desc)
{
	int i;

	for_each_krgnode_mask(i, desc->nodes){
		struct rpc_desc_recv* desc_recv = desc->desc_recv[i];

		desc->desc_recv[i] = NULL;

		if (unlikely(!list_empty(&desc_recv->list_desc_head)))
			__rpc_end_unpack_clean_queue(&desc_recv->list_desc_head);
		if (unlikely(!list_empty(&desc_recv->list_signal_head)))
			__rpc_end_unpack_clean_queue(&desc_recv->list_signal_head);

		kmem_cache_free(rpc_desc_recv_cachep, desc_recv);
	}
	
	return 0;
}

int rpc_end(struct rpc_desc* desc, int flags)
{
	struct rpc_desc_send *rpc_desc_send;
	spinlock_t *hash_lock;
	int err;

	lockdep_off();
	
	err = __rpc_end_pack(desc);

	switch(desc->type){
	case RPC_RQ_CLT:{
		int i;

		for_each_krgnode_mask(i, desc->nodes){
			__rpc_end_unpack(desc->desc_recv[i]);
		}
		break;
	}
	case RPC_RQ_SRV:
		
		__rpc_end_unpack(desc->desc_recv[0]);
		break;
	default:
		printk("unexpected case\n");
		BUG();
	}

	hash_lock = desc->hash_lock;
	if (hash_lock) {
		spin_lock_bh(hash_lock);
		spin_lock(&desc->desc_lock);

		desc->state = RPC_STATE_END;

		rpc_desc_table_remove(desc);
		desc->hash_lock = NULL;

		spin_unlock(&desc->desc_lock);
		spin_unlock_bh(hash_lock);
	}

	__rpc_emergency_send_buf_free(desc);

	rpc_desc_send = desc->desc_send;
	desc->desc_send = NULL;
	kmem_cache_free(rpc_desc_send_cachep, rpc_desc_send);

	__rpc_end_unpack_clean(desc);

	rpc_connection_set_put(desc->conn_set);
	rpc_communicator_put(desc->comm);

	if(desc->__synchro)
		__rpc_synchro_put(desc->__synchro);

	rpc_desc_put(desc);

	lockdep_on();
	return err;
}

int rpc_cancel_pack(struct rpc_desc* desc)
{
	int last_pack;
	unsigned long seq_id;
	int err = 0;

	BUG_ON(rpc_desc_forwarded(desc));

	if (desc->desc_send->flags & RPC_FLAGS_CLOSED)
		goto out;

	last_pack = list_empty(&desc->desc_send->list_desc_head);
	if (last_pack) {
		seq_id = atomic_inc_return(&desc->desc_send->seq_id);
	} else {
		struct rpc_desc_elem *next;

		next = list_entry(desc->desc_send->list_desc_head.next,
				  struct rpc_desc_elem, list_desc_elem);
		seq_id = next->seq_id;
	}

	err = __rpc_send(desc, seq_id,
			 __RPC_HEADER_FLAGS_CANCEL_PACK,
			 0, 0,
			 RPC_FLAGS_EMERGENCY_BUF);

	/*
	 * if RPC_FLAGS_EMERGENCY_BUF was used too many times, then
	 * either MAX_EMERGENCY_SEND should be increased or the caller fixed.
	 */
	WARN_ON(err);
	if (!err)
		desc->desc_send->flags |= RPC_FLAGS_CLOSED;
	else if (last_pack)
		/* Allow caller to retry */
		atomic_dec(&desc->desc_send->seq_id);

out:
	return err;
}

void rpc_cancel_unpack_from(struct rpc_desc *desc, kerrighed_node_t node)
{
	struct rpc_desc_recv *desc_recv = desc->desc_recv[node];

	BUG_ON(rpc_desc_forwarded(desc));

	set_bit(__RPC_FLAGS_CLOSED, &desc_recv->flags);
	/* TODO: send a notification to the sender so that it stops sending */
}

void rpc_cancel_unpack(struct rpc_desc* desc)
{
	kerrighed_node_t node;

	for_each_krgnode_mask(node, desc->nodes)
		rpc_cancel_unpack_from(desc, node);
}

int rpc_cancel(struct rpc_desc* desc){
	int err;

	err = rpc_cancel_pack(desc);
	rpc_cancel_unpack(desc);

	return err;
}

static
int __rpc_unpack_from_node(struct rpc_desc *desc, kerrighed_node_t node,
			   int flags, void *data, size_t size);

int rpc_cancel_sync(struct rpc_desc *desc)
{
	kerrighed_node_t node;
	struct rpc_data data;
	int err;

	err = rpc_cancel_pack(desc);
	if (err)
		return err;

	for_each_krgnode_mask(node, desc->nodes) {
		do {
			err = __rpc_unpack_from_node(desc, node, RPC_FLAGS_NOCOPY, &data, 0);
			if (!err)
				rpc_free_buffer(&data);
		} while (err != -ECANCELED);
	}

	return 0;
}

static
struct rpc_desc *
forward_rpc_desc_setup(struct rpc_desc *desc, kerrighed_node_t target)
{
	struct rpc_desc *fwd_desc;

	fwd_desc = rpc_desc_alloc();
	if (!fwd_desc)
		return NULL;

	fwd_desc->desc_send = rpc_desc_send_alloc();
	if (!fwd_desc->desc_send)
		goto err_desc_send;
	/* fwd_desc->desc_recv = NULL; */

	rpc_communicator_get(desc->comm);
	fwd_desc->comm = desc->comm;
	krgnode_set(target, fwd_desc->nodes);
	fwd_desc->conn_set = rpc_connection_set_alloc(fwd_desc->comm,
						      &fwd_desc->nodes);
	if (IS_ERR(fwd_desc->conn_set))
		goto err_conn_set;

	/* First __rpc_send() will set fwd_desc->desc_id */
	fwd_desc->type = RPC_RQ_FWD;
	fwd_desc->client = desc->client;
	fwd_desc->server = desc->server;
	fwd_desc->client_desc_id = desc->client_desc_id;
	fwd_desc->rpcid = desc->rpcid;
	/* fwd_desc->service = NULL; */
	/* fwd_desc->thread = NULL; */
	/* fwd_desc->hash_lock = NULL; */

	if (__rpc_emergency_send_buf_alloc(fwd_desc, 0))
		goto err_emergency_buf;

	fwd_desc->state = RPC_STATE_RUN;

	return fwd_desc;

err_emergency_buf:
	rpc_connection_set_put(fwd_desc->conn_set);
err_conn_set:
	rpc_communicator_put(fwd_desc->comm);
	kmem_cache_free(rpc_desc_send_cachep, fwd_desc->desc_send);
err_desc_send:
	rpc_desc_put(fwd_desc);
	return NULL;
}

static void forward_rpc_desc_cleanup(struct rpc_desc *desc)
{
	__rpc_emergency_send_buf_free(desc);
	rpc_connection_set_put(desc->conn_set);
	rpc_communicator_put(desc->comm);
	kmem_cache_free(rpc_desc_send_cachep, desc->desc_send);
	rpc_desc_put(desc);
}

int rpc_forward(struct rpc_desc *desc, kerrighed_node_t node)
{
	struct rpc_desc_send *desc_send = desc->desc_send;
#ifdef CONFIG_KRG_DEBUG
	int nr_send_later;
#endif
	struct rpc_desc_recv *desc_recv = desc->desc_recv[0];
	struct rpc_desc *fwd_desc;
	LIST_HEAD(queue);
	struct rpc_desc_elem *elem;
	int err;

	BUG_ON(desc->type != RPC_RQ_SRV);
	BUG_ON(rpc_desc_forwarded(desc));
	/*
	 * Only simple cases are supported:
	 * client should not do more pack() (hard to check reliably),
	 * no immediate pack() from server should be done yet,
	 * no rpc_signal().
	 */
#ifdef CONFIG_KRG_DEBUG
	nr_send_later = 0;
	list_for_each_entry(elem, &desc_send->list_desc_head, list_desc_elem)
		nr_send_later++;
	BUG_ON(atomic_read(&desc_send->seq_id) != nr_send_later);
#endif

	if (desc_send->flags & RPC_FLAGS_CLOSED)
		return -EPIPE;

	__rpc_end_unpack(desc_recv);

	spin_lock_bh(&desc->desc_lock);
	BUG_ON(!list_empty(&desc_recv->list_signal_head));
	list_splice_init(&desc_recv->list_desc_head, &queue);
	spin_unlock_bh(&desc->desc_lock);

	list_for_each_entry_reverse(elem, &queue, list_desc_elem)
		if (elem->flags & __RPC_HEADER_FLAGS_CANCEL_PACK) {
			set_bit(__RPC_FLAGS_CLOSED, &desc_recv->flags);
			err = -EPIPE;
			goto out_restore_queue;
		}

	err = -ENOMEM;
	fwd_desc = forward_rpc_desc_setup(desc, node);
	if (!fwd_desc)
		goto out_restore_queue;

	desc->forwarded = 1;

	err = 0;
	list_for_each_entry(elem, &queue, list_desc_elem) {
		err = __rpc_send(fwd_desc, elem->seq_id,
				 elem->flags | __RPC_HEADER_FLAGS_FORWARD,
				 elem->data, elem->size,
				 0);
		if (err) {
			__rpc_send(fwd_desc, elem->seq_id,
				   __RPC_HEADER_FLAGS_CANCEL_PACK |
				   __RPC_HEADER_FLAGS_FORWARD,
				   0, 0,
				   RPC_FLAGS_EMERGENCY_BUF);
			desc->forwarded = 0;
			break;
		}
	}

	forward_rpc_desc_cleanup(fwd_desc);

out_restore_queue:
	spin_lock_bh(&desc->desc_lock);
	BUG_ON(!list_empty(&desc_recv->list_desc_head));
	list_splice(&queue, &desc_recv->list_desc_head);
	spin_unlock_bh(&desc->desc_lock);

	return err;
}

int rpc_pack(struct rpc_desc* desc, int flags, const void* data, size_t size)
{
	int err = -EPIPE;

	BUG_ON(rpc_desc_forwarded(desc));

	if (desc->desc_send->flags & RPC_FLAGS_CLOSED)
		goto out;

	if (flags & RPC_FLAGS_LATER) {
		struct rpc_desc_elem *descelem;

		err = -ENOMEM;
		descelem = kmem_cache_alloc(rpc_desc_elem_cachep, GFP_ATOMIC);
		if (!descelem)
			goto out;

		descelem->data = (void *) data;
		descelem->size = size;
		descelem->seq_id = atomic_inc_return(&desc->desc_send->seq_id);

		list_add_tail(&descelem->list_desc_elem,
			      &desc->desc_send->list_desc_head); 
		return descelem->seq_id;
	}

	err = __rpc_send(desc, atomic_inc_return(&desc->desc_send->seq_id), 0,
			 data, size,
			 0);
	if (err)
		/* Allow caller to retry or cancel */
		atomic_dec(&desc->desc_send->seq_id);

out:
	return err;
}

int rpc_wait_pack(struct rpc_desc* desc, int seq_id)
{
	struct rpc_desc_elem *descelem, *safe;
	int err;
	int last_seq_id = 0;

	BUG_ON(rpc_desc_forwarded(desc));

	if (!list_empty(&desc->desc_send->list_desc_head)) {
		list_for_each_entry_safe(descelem, safe,
					 &desc->desc_send->list_desc_head,
					 list_desc_elem) {
			if (descelem->seq_id > seq_id)
				break;

			err = -EPIPE;
			if (!(desc->desc_send->flags & RPC_FLAGS_CLOSED))
				err = __rpc_send(desc, descelem->seq_id, 0,
						 descelem->data, descelem->size,
						 0);
			if (err) {
				seq_id = last_seq_id;
				break;
			}
			last_seq_id = descelem->seq_id;
			list_del(&descelem->list_desc_elem);
			kmem_cache_free(rpc_desc_elem_cachep, descelem);
		}
	}

	return seq_id;
}

static void __rpc_signal_dequeue_pending(struct rpc_desc *desc,
					 struct rpc_desc_recv *desc_recv,
					 struct list_head *head)
{
	struct rpc_desc_elem *descelem, *tmp_elem;
	unsigned long seq_id;

	seq_id = desc_recv->iter ? desc_recv->iter->seq_id : 0;
	list_for_each_entry_safe(descelem, tmp_elem,
				 &desc_recv->list_signal_head, list_desc_elem) {
		if (descelem->seq_id > seq_id
		    || (descelem->flags & __RPC_HEADER_FLAGS_SIGACK))
			break;
		list_move_tail(&descelem->list_desc_elem, head);
	}
}

static void __rpc_signal_deliver_pending(struct rpc_desc *desc,
					 struct list_head *head)
{
	struct rpc_desc_elem *descelem, *tmp_elem;

	list_for_each_entry_safe(descelem, tmp_elem, head, list_desc_elem) {
		list_del(&descelem->list_desc_elem);
		rpc_do_signal(desc, descelem);
	}
}

void rpc_signal_deliver_pending(struct rpc_desc *desc,
				struct rpc_desc_recv *desc_recv)
{
	LIST_HEAD(signals_head);

	spin_lock_bh(&desc->desc_lock);
	if (unlikely(!list_empty(&desc_recv->list_signal_head)))
		__rpc_signal_dequeue_pending(desc, desc_recv, &signals_head);
	spin_unlock_bh(&desc->desc_lock);
	if (unlikely(!list_empty(&signals_head)))
		__rpc_signal_deliver_pending(desc, &signals_head);
}

/* Dequeue sigacks up to ones sent after the next data to unpack */
static
struct rpc_desc_elem *
__rpc_signal_dequeue_sigack(struct rpc_desc *desc,
			    struct rpc_desc_recv *desc_recv)
{
	struct rpc_desc_elem *ret = NULL;

	if (unlikely(!list_empty(&desc_recv->list_signal_head))) {
		struct rpc_desc_elem *sig;
		unsigned long seq_id;

		seq_id = desc_recv->iter ? desc_recv->iter->seq_id : 0;
		sig = list_entry(desc_recv->list_signal_head.next,
				 struct rpc_desc_elem, list_desc_elem);
		if ((sig->flags & __RPC_HEADER_FLAGS_SIGACK)
		    && sig->seq_id <= seq_id + 1) {
			list_del(&sig->list_desc_elem);
			ret = sig;
		}
	}

	return ret;
}

static
int __rpc_unpack_from_node(struct rpc_desc* desc, kerrighed_node_t node,
			   int flags, void* data, size_t size)
{
	struct rpc_desc_elem *descelem;
	struct rpc_desc_recv* desc_recv = desc->desc_recv[node];
	LIST_HEAD(signals_head);
	LIST_HEAD(sigacks_head);
	atomic_t seq_id;

	BUG_ON(!desc);
	BUG_ON(rpc_desc_forwarded(desc));

	if (unlikely(test_bit(__RPC_FLAGS_REPOST, &desc_recv->flags)))
		atomic_set(&seq_id, atomic_read(&desc_recv->seq_id));
	else
		atomic_set(&seq_id, atomic_inc_return(&desc_recv->seq_id));

 restart:
	spin_lock_bh(&desc->desc_lock);

	if (test_bit(__RPC_FLAGS_CLOSED, &desc_recv->flags)) {
		spin_unlock_bh(&desc->desc_lock);
		return -ECANCELED;
	}

	/* Return rpc_signalacks ASAP */
	if (unlikely(!list_empty(&desc_recv->list_signal_head))) {
		for (;;) {
			descelem = __rpc_signal_dequeue_sigack(desc, desc_recv);
			if (!descelem)
				break;
			if (flags & RPC_FLAGS_SIGACK) {
				spin_unlock_bh(&desc->desc_lock);
				rpc_desc_elem_free(descelem);
				set_bit(__RPC_FLAGS_REPOST, &desc_recv->flags);
				return -ESIGACK;
			}
			/* Store discarded sigacks in a list to free them with
			 * desc_lock released */
			list_add(&descelem->list_desc_elem, &sigacks_head);
		}
	}

	if (desc_recv->iter == NULL) {

		if (list_empty(&desc_recv->list_desc_head)) {
			goto __restart;
		} else {

			descelem = container_of(desc_recv->list_desc_head.next,
						struct rpc_desc_elem,
						list_desc_elem);

			if (descelem->seq_id != 1) {
				goto __restart;
			}
			desc_recv->iter = descelem;
		}
	} else {
		struct rpc_desc_elem *next_desc_recv;

		if (list_is_last(&desc_recv->iter->list_desc_elem,
				 &desc_recv->list_desc_head)) {
			goto __restart;
		}

		next_desc_recv = container_of(desc_recv->iter->list_desc_elem.next,
					      struct rpc_desc_elem,
					      list_desc_elem);

		if (desc_recv->iter->seq_id+1 != next_desc_recv->seq_id) {
			goto __restart;
		}
		desc_recv->iter = next_desc_recv;
	}
	atomic_dec(&desc_recv->nbunexpected);

	/* Signals sent right after the matching pack() must be delivered
	 * now (actually with desc_recv's lock released). */
	if (unlikely(!list_empty(&desc_recv->list_signal_head)))
		__rpc_signal_dequeue_pending(desc, desc_recv, &signals_head);

	spin_unlock_bh(&desc->desc_lock);

	if (unlikely(!list_empty(&signals_head)))
		__rpc_signal_deliver_pending(desc, &signals_head);
	if (unlikely(!list_empty(&sigacks_head)))
		__rpc_end_unpack_clean_queue(&sigacks_head);

	if (desc_recv->iter->flags & __RPC_HEADER_FLAGS_CANCEL_PACK) {
		set_bit(__RPC_FLAGS_CLOSED, &desc_recv->flags);
		return -ECANCELED;
	}

	if (flags & RPC_FLAGS_NOCOPY) {
		struct rpc_data *rpc_data = data;

		__rpc_get_raw_data(desc_recv->iter->raw);

		rpc_data->raw = desc_recv->iter->raw;
		rpc_data->data = desc_recv->iter->data;
		rpc_data->size = size;

	} else if (desc_recv->iter->size <= size) {
		memcpy(data, desc_recv->iter->data, desc_recv->iter->size);
	} else {
		printk("unsufficient room for received packet (%d  %lu-%lu)!\n",
		       desc->rpcid,
		       desc->desc_id, desc_recv->iter->seq_id);
		BUG();
	}

	clear_bit(__RPC_FLAGS_REPOST, &desc_recv->flags);
	return 0;

 __restart:
	if (flags&RPC_FLAGS_NOBLOCK) {
		struct rpc_desc_elem *descelem;

		descelem = kmem_cache_alloc(rpc_desc_elem_cachep, GFP_ATOMIC);
		if (!descelem) {
			printk("OOM in __rpc_unpack_from_node\n");
			BUG();
		}
		
		descelem->data = data;
		descelem->size = size;
		descelem->seq_id = atomic_read(&seq_id);
		
		list_add_tail(&descelem->list_desc_elem,
			      &desc_recv->list_provided_head); 

		if (!desc_recv->iter_provided)
			desc_recv->iter_provided = descelem;
		
		spin_unlock_bh(&desc->desc_lock);
		clear_bit(__RPC_FLAGS_REPOST, &desc_recv->flags);
		return 0;
	}

	desc->thread = current;
	desc->wait_from = node;
	desc->state = RPC_STATE_WAIT1;
	set_current_state(flags & RPC_FLAGS_INTR ? TASK_INTERRUPTIBLE : TASK_UNINTERRUPTIBLE);
	spin_unlock_bh(&desc->desc_lock);

	schedule();
	if (signal_pending(current) && (flags & RPC_FLAGS_INTR)) {
		set_bit(__RPC_FLAGS_REPOST, &desc_recv->flags);
		return -EINTR;
	}

	goto restart;
}

int rpc_unpack(struct rpc_desc* desc, int flags, void* data, size_t size)
{
	switch(desc->type){
	case RPC_RQ_CLT:{
		kerrighed_node_t node;
		// ASSUME that only one node is set in desc->nodes
		// If it's not a single request, the result of this function (in this case)
		// is UNDEFINED

		BUG_ON(krgnodes_weight(desc->nodes)!=1);
		
		node = first_krgnode(desc->nodes);
		
		BUG_ON(node >= KERRIGHED_MAX_NODES);
		
		return __rpc_unpack_from_node(desc, node, flags, data, size);
	}
	case RPC_RQ_SRV:
		return __rpc_unpack_from_node(desc, 0, flags, data, size);
	default:
		printk("unexpected case\n");
		BUG();
	}
	
	return 0;
}

int rpc_unpack_from(struct rpc_desc* desc, kerrighed_node_t node,
		    int flags, void* data, size_t size)
{
	switch(desc->type){
	case RPC_RQ_CLT:
		return __rpc_unpack_from_node(desc, node, flags, data, size);
	case RPC_RQ_SRV:
		if(node == desc->client)
			return __rpc_unpack_from_node(desc, 0, flags, data, size);
		return 0;
	default:
		printk("unexpected case\n");
		BUG();
	}

	return 0;
}

/*
 * Returns KERRIGHED_MAX_NODES if no node returned yet,
 * or releases desc->lock and returns a valid node id
 *                                    or an error code when retrieving a value.
 */
static kerrighed_node_t __rpc_check_return(struct rpc_desc *desc, int *value)
{
	kerrighed_node_t node;
	int err;

	for(node=0;node<KERRIGHED_MAX_NODES;node++){
		if(desc->desc_recv[node]
		   && (atomic_read(&desc->desc_recv[node]->nbunexpected)
		       || test_bit(__RPC_FLAGS_CLOSED,
				   &desc->desc_recv[node]->flags))) {

			spin_unlock_bh(&desc->desc_lock);

			if (value) {
				err = rpc_unpack_type_from(desc, node, *value);
				if (err) {
					if (err > 0)
						err = -EPIPE;
					return err;
				}
			}

			break;
		}
	}

	return node;
}

kerrighed_node_t rpc_check_return(struct rpc_desc *desc, int *value)
{
	kerrighed_node_t ret;

	BUG_ON(desc->type != RPC_RQ_CLT);

	spin_lock_bh(&desc->desc_lock);
	ret = __rpc_check_return(desc, value);
	if (ret == KERRIGHED_MAX_NODES) {
		spin_unlock_bh(&desc->desc_lock);

		ret = -EAGAIN;
	}

	return ret;
}

kerrighed_node_t rpc_wait_return(struct rpc_desc *desc, int *value)
{
	kerrighed_node_t ret = -EPIPE;

	BUG_ON(desc->type != RPC_RQ_CLT);

	for (;;) {
		spin_lock_bh(&desc->desc_lock);
		ret = __rpc_check_return(desc, value);
		if (ret != KERRIGHED_MAX_NODES)
			break;

		desc->state = RPC_STATE_WAIT;
		desc->thread = current;
		__set_current_state(TASK_UNINTERRUPTIBLE);
		spin_unlock_bh(&desc->desc_lock);

		schedule();
	}

	return ret;
}

int rpc_wait_all(struct rpc_desc *desc)
{
	int i;
	
	if(desc->type != RPC_RQ_CLT)
		return -1;

	// on doit tester si tous les retours sont effectuee
	// (comment definir qu'un retour est acheve ? variable d'etat dans desc_recv ?)
	// tant qu'il reste des retours a effectuer, on attend et on boucle

	for_each_krgnode_mask(i, desc->nodes){

		if(list_empty(&desc->desc_recv[i]->list_provided_head))
			continue;
		
		spin_lock_bh(&desc->desc_lock);
		desc->state = RPC_STATE_WAIT;
		desc->thread = current;
		set_current_state(TASK_INTERRUPTIBLE);
		spin_unlock_bh(&desc->desc_lock);

		schedule();

	}
	
	return 0;
}

void rpc_desc_wake_up(struct rpc_desc *desc)
{
	desc->state = RPC_STATE_RUN;
	wake_up_process(desc->thread);
}

void rpc_desc_cancel_wait(struct rpc_desc *desc, kerrighed_node_t node)
{
	bool do_wakeup = false;

	spin_lock_bh(&desc->desc_lock);
	switch (desc->type) {
	case RPC_RQ_CLT:
		do_wakeup = (desc->state == RPC_STATE_WAIT1
			     && desc->wait_from == node)
			    || desc->state == RPC_STATE_WAIT;
		break;
	case RPC_RQ_SRV:
		do_wakeup = desc->state == RPC_STATE_WAIT1
			    || desc->state == RPC_STATE_WAIT;
		break;
	default:
		BUG();
	}

	set_bit(__RPC_FLAGS_CLOSED, &desc->desc_recv[node]->flags);

	if (do_wakeup)
		rpc_desc_wake_up(desc);
	spin_unlock_bh(&desc->desc_lock);
}

int rpc_signal(struct rpc_desc* desc, int sigid)
{
	if (desc->desc_send->flags & RPC_FLAGS_CLOSED)
		return -EPIPE;
	return __rpc_send(desc, atomic_read(&desc->desc_send->seq_id),
			  __RPC_HEADER_FLAGS_SIGNAL,
			  &sigid, sizeof(sigid),
			  0);
}

int __rpc_signalack(struct rpc_desc* desc)
{
	int v;

	if (desc->desc_send->flags & RPC_FLAGS_CLOSED)
		return -EPIPE;
	return __rpc_send(desc, atomic_read(&desc->desc_send->seq_id),
			  __RPC_HEADER_FLAGS_SIGNAL | __RPC_HEADER_FLAGS_SIGACK,
			  &v, sizeof(v),
			  0);
}

void rpc_free_buffer(struct rpc_data *rpc_data)
{
	__rpc_put_raw_data(rpc_data->raw);
}

int rpclayer_init(void)
{
	spin_lock_init(&lock_id);
	return 0;
}

void rpclayer_cleanup(void){
}
