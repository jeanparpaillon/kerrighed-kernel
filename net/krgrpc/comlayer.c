/**
 *
 *  Copyright (C) 2007-2008 Pascal Gallard, Kerlabs <Pascal.Gallard@kerlabs.com>
 *
 */

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/tipc.h>
#include <linux/tipc_config.h>
#include <linux/irqflags.h>
#include <linux/workqueue.h>
#include <linux/spinlock.h>
#include <linux/lockdep.h>
#include <linux/sysrq.h>
#include <linux/netdevice.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <net/tipc/tipc.h>
#include <net/tipc/tipc_plugin_port.h>
#include <net/tipc/tipc_plugin_if.h>
#include <kerrighed/krgnodemask.h>
#include <kerrighed/sys/types.h>
#include <kerrighed/krginit.h>

#include <net/krgrpc/rpcid.h>
#include <net/krgrpc/rpc.h>

#include "rpc_internal.h"

#define TIPC_KRG_SERVER_TYPE (1+TIPC_RESERVED_TYPES)

#define ACK_CLEANUP_WINDOW_SIZE 100
#define MAX_CONSECUTIVE_RECV 1000

#define REJECT_BACKOFF (HZ / 2)

#define ACK_CLEANUP_WINDOW_SIZE__LOWMEM_MODE 20
#define MAX_CONSECUTIVE_RECV__LOWMEM_MODE 20

struct tx_engine {
	struct list_head delayed_tx_queue;
	struct delayed_work delayed_tx_work; /* messages cannot be transmetted immediately */
	struct list_head not_retx_queue; /* messages accepted by TIPC */
	struct delayed_work cleanup_not_retx_work;
	struct list_head retx_queue; /* messages refused by TIPC */
	struct rpc_tx_elem *retx_iter;
	struct delayed_work retx_work;
	struct delayed_work unreachable_work;
	struct delayed_work reachable_work;
};

static DEFINE_PER_CPU(struct tx_engine, tipc_tx_engine);
static DEFINE_SPINLOCK(tipc_tx_queue_lock);

static LIST_HEAD(tipc_ack_head);
static DEFINE_SPINLOCK(tipc_ack_list_lock);
static void tipc_send_ack_worker(struct work_struct *work);
static DECLARE_DELAYED_WORK(tipc_ack_work, tipc_send_ack_worker);

struct tipc_connection {
	struct rpc_connection conn;
	atomic_long_t send_seq_id;
	unsigned long send_ack_id;
	unsigned long last_cleanup_ack;
	struct sk_buff_head rx_queue;
	struct delayed_work run_rx_queue_work;
	unsigned long recv_seq_id;
	struct list_head ack_list;
	int consecutive_recv;
};

static inline struct tipc_connection *to_ll(struct rpc_connection *conn)
{
	return container_of(conn, struct tipc_connection, conn);
}

struct workqueue_struct *krgcom_wq;

#ifdef CONFIG_64BIT

static atomic64_t consumed_bytes;

static inline void consumed_bytes_add(long load)
{
	atomic64_add(load, &consumed_bytes);
}

static inline void consumed_bytes_sub(long load)
{
	atomic64_sub(load, &consumed_bytes);
}

s64 rpc_consumed_bytes(void)
{
	return atomic64_read(&consumed_bytes);
}

#else /* !CONFIG_64BIT */

static s64 consumed_bytes;
static DEFINE_SPINLOCK(consumed_bytes_lock);

static inline void consumed_bytes_add(long load)
{
	unsigned long flags;

	spin_lock_irqsave(&consumed_bytes_lock, flags);
	consumed_bytes += load;
	spin_unlock_irqrestore(&consumed_bytes_lock, flags);
}

static inline void consumed_bytes_sub(long load)
{
	unsigned long flags;

	spin_lock_irqsave(&consumed_bytes_lock, flags);
	consumed_bytes -= load;
	spin_unlock_irqrestore(&consumed_bytes_lock, flags);
}

s64 rpc_consumed_bytes(void)
{
	unsigned long flags;
	s64 ret;

	spin_lock_irqsave(&consumed_bytes_lock, flags);
	ret = consumed_bytes;
	spin_unlock_irqrestore(&consumed_bytes_lock, flags);

	return ret;
}

#endif /* !CONFIG_64BIT */

/*
 * Local definition
 */

u32 tipc_user_ref = 0;
u32 tipc_port_ref;
DEFINE_PER_CPU(u32, tipc_send_ref);
struct tipc_name_seq tipc_seq;

static int ack_cleanup_window_size;
static int max_consecutive_recv[KERRIGHED_MAX_NODES];

void __rpc_put_raw_data(void *data){
	kfree_skb((struct sk_buff*)data);
}

void __rpc_get_raw_data(void *data){
	skb_get((struct sk_buff*)data);
}

static
inline int __send_iovec(kerrighed_node_t node, int nr_iov, struct iovec *iov)
{
	struct tipc_name name = {
		.type = TIPC_KRG_SERVER_TYPE,
		.instance = node
	};
	struct tipc_connection *conn = to_ll(static_communicator.conn[node]);
	struct __rpc_header *h = iov[0].iov_base;
	int err;

	h->link_ack_id = conn->recv_seq_id - 1;
	lockdep_off();
	err = tipc_send2name(per_cpu(tipc_send_ref, smp_processor_id()),
			     &name, 0,
			     nr_iov, iov);
	lockdep_on();
	if (err > 0)
		err = 0;
	if (!err)
		conn->consecutive_recv = 0;

	return err;
}

static
inline int send_iovec(kerrighed_node_t node, int nr_iov, struct iovec *iov)
{
	int err;

	local_bh_disable();
	err = __send_iovec(node, nr_iov, iov);
	local_bh_enable();

	return err;
}

static struct rpc_tx_elem *__rpc_tx_elem_alloc(size_t size, int nr_dest)
{
	struct rpc_tx_elem *elem;

	elem = kmem_cache_alloc(rpc_tx_elem_cachep, GFP_ATOMIC);
	if (!elem)
		goto oom;
	consumed_bytes_add(size);
	elem->data = kmalloc(size, GFP_ATOMIC);
	if (!elem->data)
		goto oom_free_elem;
	elem->link_seq_id = kmalloc(sizeof(*elem->link_seq_id) * nr_dest,
				    GFP_ATOMIC);
	elem->iov[1].iov_len = size;
	if (!elem->link_seq_id)
		goto oom_free_data;

	return elem;

oom_free_data:
	kfree(elem->data);
oom_free_elem:
	consumed_bytes_sub(size);
	kmem_cache_free(rpc_tx_elem_cachep, elem);
oom:
	return NULL;
}

static void __rpc_tx_elem_free(struct rpc_tx_elem *elem)
{
	kfree(elem->link_seq_id);
	kfree(elem->data);
	consumed_bytes_sub(elem->iov[1].iov_len);
	kmem_cache_free(rpc_tx_elem_cachep, elem);
}

static int __rpc_tx_elem_send(struct rpc_tx_elem *elem, int link_seq_index,
			      kerrighed_node_t node)
{
	struct tipc_connection *conn = to_ll(static_communicator.conn[node]);
	int err = 0;

	elem->h.link_seq_id = elem->link_seq_id[link_seq_index];
	if (elem->h.link_seq_id <= conn->send_ack_id)
		goto out;

	/* try to send */
	err = send_iovec(node, ARRAY_SIZE(elem->iov), elem->iov);

out:
	return err;
}

static void send_acks(struct tipc_connection *conn)
{
	spin_lock_bh(&tipc_ack_list_lock);
	if (list_empty(&conn->ack_list)) {
		rpc_connection_get(&conn->conn);
		list_add_tail(&conn->ack_list, &tipc_ack_head);
		queue_delayed_work(krgcom_wq, &tipc_ack_work, 0);
	}
	spin_unlock_bh(&tipc_ack_list_lock);
}

static
void tipc_send_ack_worker(struct work_struct *work)
{
	LIST_HEAD(ack_head);
	struct iovec iov[1];
	struct __rpc_header h;
	struct tipc_connection *conn, *safe;
	int err;

	spin_lock_bh(&tipc_ack_list_lock);
	list_splice_init(&tipc_ack_head, &ack_head);
	spin_unlock_bh(&tipc_ack_list_lock);

	h.from = kerrighed_node_id;
	h.rpcid = RPC_ACK;
	h.flags = 0;

	iov[0].iov_base = &h;
	iov[0].iov_len = sizeof(h);

	list_for_each_entry_safe(conn, safe, &ack_head, ack_list) {
		spin_lock_bh(&tipc_ack_list_lock);
		list_del_init(&conn->ack_list);
		spin_unlock_bh(&tipc_ack_list_lock);

		err = send_iovec(conn->conn.peer, ARRAY_SIZE(iov), iov);
		if (err)
			send_acks(conn);
		rpc_connection_put(&conn->conn);
	}
}

static void tipc_delayed_tx_worker(struct work_struct *work)
{
	struct tx_engine *engine = container_of(work, struct tx_engine, delayed_tx_work.work);
	LIST_HEAD(queue);
	LIST_HEAD(not_retx_queue);
	struct rpc_tx_elem *iter;
	struct rpc_tx_elem *safe;

	lockdep_off();

	// get the waiting list
	spin_lock_bh(&tipc_tx_queue_lock);
	list_splice_init(&engine->delayed_tx_queue, &queue);
	spin_unlock_bh(&tipc_tx_queue_lock);

	if(list_empty(&queue))
		goto exit_empty;

	// browse the waiting list
	list_for_each_entry_safe(iter, safe, &queue, tx_queue){
		krgnodemask_t nodes;
		kerrighed_node_t link_seq_index, node;

		link_seq_index = iter->link_seq_index;
		if (link_seq_index) {
			/* Start with the first node to which we could not
			 * transmit */
			krgnodes_setall(nodes);
			krgnodes_shift_left(nodes, nodes, iter->index);
			krgnodes_and(nodes, nodes, iter->nodes);
		} else {
			/* Transmit to all nodes */
			krgnodes_copy(nodes, iter->nodes);
		}
		for_each_krgnode_mask(node, nodes){
			int err;

			err = __rpc_tx_elem_send(iter, link_seq_index, node);
			if (err < 0) {
				iter->index = node;
				iter->link_seq_index = link_seq_index;

				goto exit;
			}

			link_seq_index++;
		}
		/* Reset the transmission cursor for future retransmissions */
		iter->index = 0;
		iter->link_seq_index = 0;

		/* The message has been transmitted to all receivers. We should not have to
		 * re-transmit it. So move it to not_retx_queue. */
		list_move_tail(&iter->tx_queue, &not_retx_queue);
	}

 exit:
	if (!list_empty(&queue)) {
		// merge the two lists
		spin_lock_bh(&tipc_tx_queue_lock);
		list_splice(&queue, &engine->delayed_tx_queue);
		list_splice(&not_retx_queue, engine->not_retx_queue.prev);
		spin_unlock_bh(&tipc_tx_queue_lock);
	} else {
		if (likely(!list_empty(&not_retx_queue))) {
			spin_lock_bh(&tipc_tx_queue_lock);
			list_splice(&not_retx_queue, engine->not_retx_queue.prev);
			spin_unlock_bh(&tipc_tx_queue_lock);
		}
	}

exit_empty:
	lockdep_on();
}

static void tipc_retx_worker(struct work_struct *work)
{
	struct tx_engine *engine = container_of(work, struct tx_engine, retx_work.work);
	LIST_HEAD(queue);
	LIST_HEAD(not_retx_queue);
	struct rpc_tx_elem *iter;
	struct rpc_tx_elem *safe;

	lockdep_off();

	// get the waiting list
	spin_lock_bh(&tipc_tx_queue_lock);
	list_splice_init(&engine->retx_queue, &queue);
	iter = engine->retx_iter;
	engine->retx_iter = NULL;
	spin_unlock_bh(&tipc_tx_queue_lock);

	if(list_empty(&queue))
		goto exit_empty;

	/* list_for_each_entry_safe_continue starts to iterate AFTER
	   the current item. So current item can be anything as long as
	   we are not trying to use it */
	if(!iter) {
		iter = list_entry(&queue,
				  struct rpc_tx_elem,
				  tx_queue);
	} else {
		/* iter points to an entry which failed to fully
		 * retransmit. Start from it. */
		iter = list_entry(iter->tx_queue.prev, struct rpc_tx_elem, tx_queue);
	}

	// browse the waiting list
	list_for_each_entry_safe_continue(iter, safe, &queue, tx_queue){
		krgnodemask_t nodes;
		kerrighed_node_t link_seq_index, node;

		link_seq_index = iter->link_seq_index;
		if (link_seq_index) {
			/* Start with the first node to which we could not
			 * transmit */
			krgnodes_setall(nodes);
			krgnodes_shift_left(nodes, nodes, iter->index);
			krgnodes_and(nodes, nodes, iter->nodes);
		} else {
			/* Transmit to all nodes */
			krgnodes_copy(nodes, iter->nodes);
		}
		for_each_krgnode_mask(node, nodes){
			int err;

			err = __rpc_tx_elem_send(iter, link_seq_index, node);
			if (err < 0) {
				iter->index = node;
				iter->link_seq_index = link_seq_index;

				goto exit;
			}

			link_seq_index++;
		}

		/* Reset the transmission cursor for future retransmissions */
		iter->index = 0;
		iter->link_seq_index = 0;

		list_move_tail(&iter->tx_queue, &not_retx_queue);
	}

	iter = NULL;

 exit:
 	if (!list_empty(&not_retx_queue)){
		spin_lock_bh(&tipc_tx_queue_lock);
		list_splice(&not_retx_queue, &engine->not_retx_queue);
		spin_unlock_bh(&tipc_tx_queue_lock);
	}

	if (!list_empty(&queue)) {
		// merge the two lists
		spin_lock_bh(&tipc_tx_queue_lock);
		list_splice(&queue, &engine->retx_queue);
		/* A concurrent run of the worker might already have set a
		 * restart point later in the queue. Do not overwrite it unless
		 * we set an earlier restart point. */
		if (iter)
			engine->retx_iter = iter;
		spin_unlock_bh(&tipc_tx_queue_lock);
	}

exit_empty:
	lockdep_on();
}

static void tipc_cleanup_not_retx_worker(struct work_struct *work)
{
	struct tx_engine *engine = container_of(work, struct tx_engine, cleanup_not_retx_work.work);
	struct rpc_tx_elem *iter;
	struct rpc_tx_elem *safe;
	LIST_HEAD(queue);
	int node;

	spin_lock_bh(&tipc_tx_queue_lock);
	list_splice_init(&engine->not_retx_queue, &queue);
	spin_unlock_bh(&tipc_tx_queue_lock);

	list_for_each_entry_safe(iter, safe, &queue, tx_queue){
		struct tipc_connection *conn;
		int need_to_free, link_seq_index;

		need_to_free = 0;
		link_seq_index = 0;

		for_each_krgnode_mask(node, iter->nodes){

			iter->h.link_seq_id = iter->link_seq_id[link_seq_index];

			conn = to_ll(static_communicator.conn[node]);
			if (iter->h.link_seq_id > conn->send_ack_id)
				goto next_iter;

			link_seq_index++;
		}
		need_to_free = 1;

	next_iter:
		if(need_to_free){
			list_del(&iter->tx_queue);
			__rpc_tx_elem_free(iter);
		}
	}

	if (!list_empty(&queue)) {
		// merge the two lists
		spin_lock_bh(&tipc_tx_queue_lock);
		list_splice(&queue, &engine->not_retx_queue);
		spin_unlock_bh(&tipc_tx_queue_lock);
	}

}

static void cleanup_not_retx(void)
{
	struct tx_engine *engine;
	int cpu;

	for_each_online_cpu(cpu) {
		engine = &per_cpu(tipc_tx_engine, cpu);
		queue_delayed_work_on(cpu, krgcom_wq,
				      &engine->cleanup_not_retx_work,0);
	}
}

static
void tipc_unreachable_node_worker(struct work_struct *work){
}

static
void tipc_reachable_node_worker(struct work_struct *work){
	struct tx_engine *engine = container_of(work, struct tx_engine, reachable_work.work);

	spin_lock_bh(&tipc_tx_queue_lock);
	list_splice_init(&engine->not_retx_queue, &engine->retx_queue);
	spin_unlock_bh(&tipc_tx_queue_lock);

	queue_delayed_work_on(smp_processor_id(), krgcom_wq,
			      &engine->retx_work, 0);
}

#define MAX_EMERGENCY_SEND 2

int __rpc_emergency_send_buf_alloc(struct rpc_desc *desc, size_t size)
{
	struct rpc_tx_elem **elem;
	int nr_dest;
	int err = 0;
	int i;

	elem = kmalloc(sizeof(*elem) * MAX_EMERGENCY_SEND, GFP_ATOMIC);
	if (!elem)
		goto oom;
	nr_dest = krgnodes_weight(desc->nodes);
	for (i = 0; i < MAX_EMERGENCY_SEND; i++) {
		elem[i] = __rpc_tx_elem_alloc(size, nr_dest);
		if (!elem[i])
			goto oom_free_elems;
	}
	desc->desc_send->emergency_send_buf = elem;

out:
	return err;

oom_free_elems:
	for (i--; i >= 0; i--)
		__rpc_tx_elem_free(elem[i]);
	kfree(elem);
oom:
	err = -ENOMEM;
	goto out;
}

void __rpc_emergency_send_buf_free(struct rpc_desc *desc)
{
	struct rpc_tx_elem **elem = desc->desc_send->emergency_send_buf;
	int i;

	/* does not buy a lot, but still can help debug */
	desc->desc_send->emergency_send_buf = NULL;
	for (i = 0; i < MAX_EMERGENCY_SEND; i++)
		if (elem[i])
			/* emergency send buf was not used */
			__rpc_tx_elem_free(elem[i]);
	kfree(elem);
}

static struct rpc_tx_elem *next_emergency_send_buf(struct rpc_desc *desc)
{
	struct rpc_tx_elem **elems = desc->desc_send->emergency_send_buf;
	struct rpc_tx_elem *buf = NULL;
	int i;

	for (i = 0; i < MAX_EMERGENCY_SEND; i++)
		if (elems[i]) {
			buf = elems[i];
			elems[i] = NULL;
			break;
		}
	return buf;
}

int __rpc_send_ll(struct rpc_desc* desc,
			 krgnodemask_t *nodes,
			 unsigned long seq_id,
			 int __flags,
			 const void* data, size_t size,
			 int rpc_flags)
{
	struct tipc_connection *conn;
	struct rpc_tx_elem* elem;
	struct tx_engine *engine;
	kerrighed_node_t node;
	int link_seq_index;

	elem = __rpc_tx_elem_alloc(size, __krgnodes_weight(nodes));
	if (!elem) {
		if (rpc_flags & RPC_FLAGS_EMERGENCY_BUF)
			elem = next_emergency_send_buf(desc);
		if (!elem)
			return -ENOMEM;
	}

	link_seq_index = 0;
	__for_each_krgnode_mask(node, nodes) {
		conn = to_ll(static_communicator.conn[node]);
		elem->link_seq_id[link_seq_index] =
			atomic_long_inc_return(&conn->send_seq_id);
		link_seq_index++;
	}
	if (rpc_flags & RPC_FLAGS_NEW_DESC_ID)
		rpc_new_desc_id_unlock(&static_communicator, desc->type == RPC_RQ_CLT);

	elem->h.from = kerrighed_node_id;
	elem->h.client = desc->client;
	elem->h.server = desc->server;
	elem->h.desc_id = desc->desc_id;
	elem->h.client_desc_id = desc->client_desc_id;
	elem->h.seq_id = seq_id;
	
	elem->h.flags = __flags;
	if(desc->type == RPC_RQ_SRV)
		elem->h.flags |= __RPC_HEADER_FLAGS_SRV_REPLY;

	elem->h.rpcid = desc->rpcid;

	elem->iov[0].iov_base = &elem->h;
	elem->iov[0].iov_len = sizeof(elem->h);
	
	elem->iov[1].iov_base = (void *) data;
	elem->iov[1].iov_len = size;

	elem->index = 0;
	elem->link_seq_index = 0;

	memcpy(elem->data, data, size);
	elem->iov[1].iov_base = elem->data;
		
	__krgnodes_copy(&elem->nodes, nodes);	

	preempt_disable();
	engine = &per_cpu(tipc_tx_engine, smp_processor_id());
	if (irqs_disabled()) {
		/* Add the packet in the tx_queue */
		lockdep_off();
		spin_lock(&tipc_tx_queue_lock);
		list_add_tail(&elem->tx_queue, &engine->delayed_tx_queue);
		spin_unlock(&tipc_tx_queue_lock);
		lockdep_on();

		/* Schedule the work ASAP */
		queue_work(krgcom_wq, &engine->delayed_tx_work.work);

	} else {
		int err = 0;

		link_seq_index = 0;
		__for_each_krgnode_mask(node, nodes){

			err = __rpc_tx_elem_send(elem, link_seq_index, node);
			if(err<0){
				spin_lock_bh(&tipc_tx_queue_lock);
				list_add_tail(&elem->tx_queue,
						&engine->retx_queue);
				spin_unlock_bh(&tipc_tx_queue_lock);
				break;
			}

			link_seq_index++;
		}

		if(err>=0){
			/* Add the packet in the not_retx_queue */
			spin_lock_bh(&tipc_tx_queue_lock);
			list_add_tail(&elem->tx_queue, &engine->not_retx_queue);
			spin_unlock_bh(&tipc_tx_queue_lock);
		}
	}
	preempt_enable();
	return 0;
}

inline
void insert_in_seqid_order(struct rpc_desc_elem* desc_elem,
			   struct rpc_desc_recv* desc_recv)
{
	struct rpc_desc_elem *iter;
	struct list_head *at;

	if (unlikely(desc_elem->flags & __RPC_HEADER_FLAGS_SIGNAL)) {
		/* For a given seq_id, queue all received sigacks
		 * before all signals, and try to preserve signals order
		 */
		int sigack = (desc_elem->flags & __RPC_HEADER_FLAGS_SIGACK);

		at = &desc_recv->list_signal_head;
		list_for_each_entry_reverse(iter, &desc_recv->list_signal_head,
					    list_desc_elem)
			if (iter->seq_id < desc_elem->seq_id
			    || (iter->seq_id == desc_elem->seq_id && !sigack)) {
				at = &iter->list_desc_elem;
				break;
			}
	} else {
		/* Data element
		 * There can be only one single element per seq_id
		 */
		at = &desc_recv->list_desc_head;
		list_for_each_entry_reverse(iter, &desc_recv->list_desc_head,
					    list_desc_elem)
			if (iter->seq_id < desc_elem->seq_id) {
				at = &iter->list_desc_elem;
				break;
			}
	}
	list_add(&desc_elem->list_desc_elem, at);
}

/*
 * do_action
 * Process the received descriptor
 *
 * desc->desc_lock must be hold
 */
static
inline
int do_action(struct rpc_desc *desc, struct __rpc_header *h)
{
	switch (desc->state) {
	case RPC_STATE_NEW:
		spin_unlock(&desc->desc_lock);
		return rpc_handle_new(desc);
	case RPC_STATE_WAIT1:
		if (desc->type == RPC_RQ_CLT
		    && desc->wait_from != h->server) {
			spin_unlock(&desc->desc_lock);
			break;
		}
	case RPC_STATE_WAIT:
		desc->state = RPC_STATE_RUN;
		wake_up_process(desc->thread);
		spin_unlock(&desc->desc_lock);
		break;
	default:
		spin_unlock(&desc->desc_lock);			
		break;
	}
	return 0;
}

void rpc_desc_elem_free(struct rpc_desc_elem *elem)
{
	kfree_skb(elem->raw);
	kmem_cache_free(rpc_desc_elem_cachep, elem);
}

void rpc_do_signal(struct rpc_desc *desc,
		   struct rpc_desc_elem *signal_elem)
{
	if (desc->thread)
		send_sig(*(int*)signal_elem->data, desc->thread, 0);

	__rpc_signalack(desc);

	rpc_desc_elem_free(signal_elem);
}

/*
 * handle_valid_desc
 * We found the right descriptor, is-there a waiting buffer ?
 */
inline
int handle_valid_desc(struct rpc_desc *desc,
		      struct rpc_desc_recv *desc_recv,
		      struct rpc_desc_elem* descelem,
		      struct __rpc_header *h,
		      struct sk_buff *buf){
	int err;

	// Update the received_packets map
	if(descelem->seq_id<sizeof(desc_recv->received_packets)*8)
		set_bit(descelem->seq_id-1, &desc_recv->received_packets);

	// is there a waiting buffer ?
	if (desc_recv->iter_provided) {

		// there are some waiting buffer. is-there one for us ?
		if (unlikely(h->flags & __RPC_HEADER_FLAGS_SIGNAL)
		    && (!(h->flags & __RPC_HEADER_FLAGS_SIGACK))) {
			struct rpc_desc_elem *provided;

			provided = list_entry(desc_recv->list_provided_head.prev,
					      struct rpc_desc_elem, list_desc_elem);
			
			if (descelem->seq_id <= provided->seq_id) {

				rpc_do_signal(desc, descelem);

				spin_unlock(&desc->desc_lock);
				return 0;
				
			} else {
				insert_in_seqid_order(descelem, desc_recv);
			}

		} else {
			
			if (desc_recv->iter_provided->seq_id == descelem->seq_id) {
				//printk("%d tipc_handler_ordered: found a waiting buffer (%lu)\n",
				//       current->pid, descelem->seq_id);
			} else {
				insert_in_seqid_order(descelem, desc_recv);
			}
		}
		
		goto do_action;
		
	}
	
	// unexpected message
	if (unlikely(h->flags & __RPC_HEADER_FLAGS_SIGNAL)
	    && (!(h->flags & __RPC_HEADER_FLAGS_SIGACK))
	    && (h->seq_id <= atomic_read(&desc_recv->seq_id))
	    && ((desc->service->flags & RPC_FLAGS_NOBLOCK) || desc->thread)) {

		rpc_do_signal(desc, descelem);

		spin_unlock(&desc->desc_lock);
		return 0;
	}
	
	insert_in_seqid_order(descelem, desc_recv);
	atomic_inc(&desc_recv->nbunexpected);
	
 do_action:
	err = do_action(desc, h);
	if (err) {
		/*
		 * Keeping this packet at this layer would need to reschedule
		 * its handling, which lower layers already do without needing
		 * more metadata. So dropping that packet at this layer is
		 * simpler and safe.
		 */
		spin_lock(&desc->desc_lock);
		/*
		 * We expect that only the first packet of a new transaction may
		 * fail to be handled by do_action(). Otherwise the packet might
		 * have been unpacked by the handler, or the handler may have
		 * played with nbunexpected.
		 */
		BUG_ON(desc->state != RPC_STATE_NEW || descelem->seq_id > 1);
		atomic_dec(&desc_recv->nbunexpected);
		list_del(&descelem->list_desc_elem);
		spin_unlock(&desc->desc_lock);
	}
	return err;
}

static
struct rpc_desc *
server_rpc_desc_setup(struct rpc_connection *conn, const struct __rpc_header *h)
{
	struct rpc_desc *desc;

	desc = rpc_desc_alloc();
	if (!desc)
		goto out;

	desc->desc_send = rpc_desc_send_alloc();
	if (!desc->desc_send)
		goto err_desc_send;

	desc->desc_recv[0] = rpc_desc_recv_alloc();
	if (!desc->desc_recv[0])
		goto err_desc_recv;

	// Since a RPC_RQ_CLT can only be received from one node:
	// by choice, we decide to use 0 as the corresponding id
	krgnode_set(0, desc->nodes);

	desc->desc_id = h->desc_id;
	desc->type = RPC_RQ_SRV;
	desc->client = h->client;
	if (h->flags & __RPC_HEADER_FLAGS_FORWARD)
		desc->server = h->server;
	else
		desc->server = kerrighed_node_id;
	desc->client_desc_id = h->client_desc_id;
	desc->rpcid = h->rpcid;
	desc->service = rpc_services[h->rpcid];
	desc->thread = NULL;

	if (__rpc_emergency_send_buf_alloc(desc, 0))
		goto err_emergency_send;

	desc->state = RPC_STATE_NEW;

	rpc_desc_get(desc);

	BUG_ON(h->desc_id != desc->desc_id);
	rpc_desc_table_add(conn->desc_srv, desc);
	desc->hash_lock = &conn->desc_done_lock;

out:
	return desc;

err_emergency_send:
	kmem_cache_free(rpc_desc_recv_cachep, desc->desc_recv[0]);
err_desc_recv:
	kmem_cache_free(rpc_desc_send_cachep, desc->desc_send);
err_desc_send:
	rpc_desc_put(desc);
	return NULL;
}

/*
 * tipc_handler_ordered
 * Packets are in the right order, so we have to find the corresponding
 * descriptor (if any).
 */
static int tipc_handler_ordered(struct tipc_connection *conn,
				struct sk_buff *buf,
				unsigned const char* data,
				unsigned int size)
{
	struct rpc_connection *rpc_conn = &conn->conn;
	unsigned char const* iter;
	struct __rpc_header *h;
	struct rpc_desc *desc;
	struct rpc_desc_elem* descelem;
	struct rpc_desc_recv* desc_recv;
	spinlock_t *hash_lock;
	int err = 0;

	iter = data;
	h = (struct __rpc_header*)iter;
	iter += sizeof(struct __rpc_header);

	/* select the right array regarding the type of request:
	   __RPC_HEADER_FLAGS_SRV_REPLY: we are the client side -> desc_clt
	   else: we are the server side -> desc_srv
	*/
	if (h->flags & __RPC_HEADER_FLAGS_SRV_REPLY)
		hash_lock = &rpc_conn->comm->desc_clt_lock;
	else
		hash_lock = &rpc_conn->desc_done_lock;

	spin_lock(hash_lock);
	if (h->flags & __RPC_HEADER_FLAGS_SRV_REPLY)
		desc = rpc_desc_table_find(rpc_conn->comm->desc_clt, h->client_desc_id);
	else
		desc = rpc_desc_table_find(rpc_conn->desc_srv, h->desc_id);

	if (desc) {

		rpc_desc_get(desc);

	} else {

		if(h->flags & __RPC_HEADER_FLAGS_SRV_REPLY){

			// requesting desc is already closed (most probably an async request
			// just discard this packet
			spin_unlock(hash_lock);
			goto out;

		}else{

			if (unlikely(h->desc_id <= rpc_conn->desc_done_id)) {
				spin_unlock(hash_lock);
				goto out;
			}

			desc = server_rpc_desc_setup(rpc_conn, h);
			if (!desc) {
				/*
				 * Drop the packet, but not silently.
				 * tipc_handler() may decide to drop more pending
				 * packets to decrease memory pressure, or keep
				 * the packet and retry handling it later.
				 */
				spin_unlock(hash_lock);
				err = -ENOMEM;
				goto out;
			}

			rpc_conn->desc_done_id = h->desc_id;

		}

	}

	BUG_ON(desc->hash_lock != hash_lock);
	if (h->flags & __RPC_HEADER_FLAGS_SRV_REPLY)
		BUG_ON(desc->desc_id != h->client_desc_id);
	else
		BUG_ON(desc->desc_id != h->desc_id);

	/* Optimization: do not allocate memory if we already know that it is
	 * useless to.
	 * If desc is valid after double check, desc_recv retrieved below will
	 * be valid too, since hash_lock acts as a memory barrier between
	 * the processor having allocated desc (and inserted it in the table)
	 * and us.
	 * If desc has a valid state here, as long as we do not release
	 * hash_lock desc_recv retrieved below is valid too (see rpc_end()).
	 */
	switch (desc->type) {
	case RPC_RQ_CLT:
		// we are in the client side (just received a msg from server)
		desc_recv = desc->desc_recv[h->server];
		break;

	case RPC_RQ_SRV:
		// we are in the server side (just received a msg from client)
		desc_recv = desc->desc_recv[0];
		break;

	case RPC_RQ_FWD:
		BUG();
		break;

	default:
		printk("unexpected case %d\n", desc->type);
		BUG();
	}
	/* Is the transaction still accepting packets? */
	if (!(desc->state & RPC_STATE_MASK_VALID) ||
	    (desc_recv->flags & RPC_FLAGS_CLOSED)) {
		spin_unlock(hash_lock);
		goto out_put;
	}

	spin_unlock(hash_lock);

	descelem = kmem_cache_alloc(rpc_desc_elem_cachep, GFP_ATOMIC);
	if (!descelem) {
		/*
		 * Same OOM handling as for new rpc_desc above, except that we
		 * keep the rpc_desc, even if we just created it, because it is
		 * now visible in the hash table and it would just add
		 * complexity to try to free it.
		 */
		err = -ENOMEM;
		goto out_put;
	}

	skb_get(buf);
	descelem->raw = buf;
	descelem->data = (void*) iter;
	descelem->seq_id = h->seq_id;
	descelem->size = size - (iter - data);
	descelem->flags = h->flags;
		
	spin_lock(&desc->desc_lock);

	/* Double-check withe desc->desc_lock held */
	if (!(desc->state & RPC_STATE_MASK_VALID) ||
	    (desc_recv->flags & RPC_FLAGS_CLOSED)) {
		// This side is closed. Discard the packet
		spin_unlock(&desc->desc_lock);
		rpc_desc_elem_free(descelem);
		goto out_put;
	}

	/* Releases desc->desc_lock */
	err = handle_valid_desc(desc, desc_recv, descelem, h, buf);
	if (err)
		/* Same OOM handling as above */
		rpc_desc_elem_free(descelem);

out_put:
	rpc_desc_put(desc);
out:
	return err;
}

static inline int handle_one_packet(struct tipc_connection *conn,
				    struct sk_buff *buf,
				    unsigned char const *data,
				    unsigned int size)
{
	int err;

	err = tipc_handler_ordered(conn, buf, data, size);
	if (!err) {
		if (conn->conn.peer == kerrighed_node_id)
			conn->send_ack_id = conn->recv_seq_id;
		conn->recv_seq_id++;
	}
	return err;
}

static void schedule_run_rx_queue(struct tipc_connection *conn);

static void run_rx_queue(struct tipc_connection *conn)
{
	struct sk_buff_head *queue;
	struct sk_buff *buf;
	struct __rpc_header *h;

	queue = &conn->rx_queue;
	while ((buf = skb_peek(queue))) {
		h = (struct __rpc_header *)buf->data;

		BUG_ON(h->link_seq_id < conn->recv_seq_id);
		if (h->link_seq_id > conn->recv_seq_id)
			break;

		if (handle_one_packet(conn, buf, buf->data, buf->len)) {
			schedule_run_rx_queue(conn);
			break;
		}

		__skb_unlink(buf, queue);
		kfree_skb(buf);
	}
}

static void run_rx_queue_worker(struct work_struct *work)
{
	struct tipc_connection *conn;

	conn = container_of(work, struct tipc_connection, run_rx_queue_work.work);
	spin_lock_bh(&conn->rx_queue.lock);
	run_rx_queue(conn);
	spin_unlock_bh(&conn->rx_queue.lock);
	rpc_connection_put(&conn->conn);
}

static void schedule_run_rx_queue(struct tipc_connection *conn)
{
	int queued;

	rpc_connection_get(&conn->conn);
	queued = queue_delayed_work(krgcom_wq, &conn->run_rx_queue_work, HZ / 2);
	if (!queued)
		rpc_connection_put(&conn->conn);
}

/*
 * tipc_handler
 * receives packets from TIPC and orders them
 */
static void tipc_handler(void *usr_handle,
			 u32 port_ref,
			 struct sk_buff **buf,
			 unsigned char const *data,
			 unsigned int size,
			 unsigned int importance,
			 struct tipc_portid const *orig,
			 struct tipc_name_seq const *dest)
{
	struct tipc_connection *conn;
	struct sk_buff_head *queue;
	struct sk_buff *__buf;
	struct __rpc_header *h;

	__buf = *buf;
	h = (struct __rpc_header*)data;
	BUG_ON(size != __buf->len);

	conn = to_ll(rpc_find_get_connection(h->from));
	queue = &conn->rx_queue;

	spin_lock(&queue->lock);

	// Update the ack value sent by the other node
	if (h->link_ack_id > conn->send_ack_id){
		conn->send_ack_id = h->link_ack_id;
		if(conn->send_ack_id - conn->last_cleanup_ack
			> ack_cleanup_window_size){
			conn->last_cleanup_ack = h->link_ack_id;
			cleanup_not_retx();
		}

	}

	if (h->rpcid == RPC_ACK)
		goto exit;

	// Check if we are not receiving an already received packet
	if (h->link_seq_id < conn->recv_seq_id) {
		send_acks(conn);
		goto exit;
	}

	// Check if we are receiving lot of packets but sending none
	if (conn->consecutive_recv >= max_consecutive_recv[h->from])
		send_acks(conn);
	conn->consecutive_recv++;

	// Is-it the next ordered message ?
	if (h->link_seq_id > conn->recv_seq_id) {
		struct sk_buff *at;
		unsigned long seq_id = h->link_seq_id;

		/*
		 * Insert in the ordered list.
		 * Optimized for in-order reception.
		 */
		skb_queue_reverse_walk(queue, at) {
			struct __rpc_header *ath;

			ath = (struct __rpc_header *)at->data;
			if (ath->link_seq_id < seq_id)
				break;
			else if (ath->link_seq_id == seq_id)
				/* Duplicate */
				goto exit;
		}
		skb_get(__buf);
		__skb_queue_after(queue, at, __buf);
		goto exit;
	}

	if (handle_one_packet(conn, __buf, data, size)) {
		skb_get(__buf);
		__skb_queue_head(queue, __buf);
		schedule_run_rx_queue(conn);
	} else {
		run_rx_queue(conn);
	}

 exit:
	spin_unlock(&queue->lock);

	rpc_connection_put(&conn->conn);
}

static
u32 port_dispatcher(struct tipc_port *p_ptr, struct sk_buff *buf)
{
	struct tipc_msg *msg = (struct tipc_msg *)buf->data;
	long cpuid = (long)p_ptr->usr_handle;
	struct tx_engine *engine = &per_cpu(tipc_tx_engine, cpuid);

	/*
	 * We might have sent something while TIPC is still setting up the
	 * connection to the peer. Retransmit after a small delay, unless the peer
	 * disconnects, in which case port_wakeup() will retransmit when
	 * possible.
	 */
	if (msg_errcode(msg) == TIPC_ERR_NO_NAME
	    && krgnode_present(msg_nameinst(msg))) {
		queue_delayed_work(krgcom_wq, &tipc_ack_work, REJECT_BACKOFF);
		queue_delayed_work_on(cpuid, krgcom_wq,
				      &engine->reachable_work, REJECT_BACKOFF);
	}

	kfree_skb(buf);
	return TIPC_OK;
}

static
void port_wakeup(struct tipc_port *p_ptr){
	long cpuid = (long)p_ptr->usr_handle;
	struct tx_engine *engine = &per_cpu(tipc_tx_engine, cpuid);

	/*
	 * Schedule the work ASAP
	 * To help the other side freeing memory, we try to favor acks and delay
	 * retx by 1 jiffy.
	 */

	queue_delayed_work(krgcom_wq, &tipc_ack_work, 0);

	queue_delayed_work_on(cpuid, krgcom_wq, &engine->retx_work, 1);
	queue_delayed_work_on(cpuid, krgcom_wq, &engine->delayed_tx_work, 1);
}

int comlayer_enable_dev(const char *name)
{
	char buf[256];
	int res;

	printk("Try to enable bearer on %s:", name);

	snprintf(buf, sizeof(buf), "eth:%s", name);

	res = tipc_enable_bearer(buf, tipc_addr(1, 1, 0), TIPC_MEDIA_LINK_PRI);
	if (res)
		printk("failed\n");
	else
		printk("ok\n");

	return res;
}

void comlayer_enable(void)
{
	struct net_device *netdev;

	read_lock(&dev_base_lock);
	for_each_netdev(&init_net, netdev)
		comlayer_enable_dev(netdev->name);
	read_unlock(&dev_base_lock);
}

int comlayer_disable_dev(const char *name)
{
	int res;

	printk("Try to disable bearer on %s:", name);

	res = tipc_disable_bearer(name);
	if (res)
		printk("failed\n");
	else
		printk("ok\n");

	return res;
}

void comlayer_disable(void)
{
	struct net_device *netdev;

	read_lock(&dev_base_lock);
	for_each_netdev(&init_net, netdev)
		comlayer_disable_dev(netdev->name);
	read_unlock(&dev_base_lock);
}

void krg_node_reachable(kerrighed_node_t nodeid){
	int cpuid;

	queue_delayed_work(krgcom_wq, &tipc_ack_work, 0);
	for_each_online_cpu(cpuid){
		struct tx_engine *engine = &per_cpu(tipc_tx_engine, cpuid);

		queue_delayed_work_on(cpuid, krgcom_wq,
				      &engine->reachable_work, 0);
	}
}

void krg_node_unreachable(kerrighed_node_t nodeid){
}

void rpc_enable_lowmem_mode(kerrighed_node_t nodeid){
	max_consecutive_recv[nodeid] = MAX_CONSECUTIVE_RECV__LOWMEM_MODE;

	send_acks(to_ll(static_communicator.conn[nodeid]));
}

void rpc_disable_lowmem_mode(kerrighed_node_t nodeid){
	max_consecutive_recv[nodeid] = MAX_CONSECUTIVE_RECV;
}

void rpc_enable_local_lowmem_mode(void){
	ack_cleanup_window_size = ACK_CLEANUP_WINDOW_SIZE__LOWMEM_MODE;
	cleanup_not_retx();
}

void rpc_disable_local_lowmem_mode(void){
	ack_cleanup_window_size = ACK_CLEANUP_WINDOW_SIZE;
}

struct rpc_connection *
rpc_connection_alloc_ll(struct rpc_communicator *comm, kerrighed_node_t node)
{
	struct tipc_connection *ll;

	ll = kmalloc(sizeof(*ll), GFP_ATOMIC);
	if (!ll)
		return NULL;

	atomic_long_set(&ll->send_seq_id, 0);
	ll->send_ack_id = 0;
	ll->last_cleanup_ack = 0;
	skb_queue_head_init(&ll->rx_queue);
	INIT_DELAYED_WORK(&ll->run_rx_queue_work, run_rx_queue_worker);
	ll->recv_seq_id = 1;
	INIT_LIST_HEAD(&ll->ack_list);
	ll->consecutive_recv = 0;

	return &ll->conn;
}

void rpc_connection_free_ll(struct rpc_connection *conn)
{
	struct tipc_connection *ll = to_ll(conn);
	BUG_ON(!list_empty(&ll->ack_list));
	BUG_ON(!skb_queue_empty(&ll->rx_queue));
	kfree(ll);
}

int comlayer_init(void)
{
	int res = 0;
	long i;

	for_each_possible_cpu(i) {
		struct tx_engine *engine = &per_cpu(tipc_tx_engine, i);
		INIT_LIST_HEAD(&engine->delayed_tx_queue);
		INIT_DELAYED_WORK(&engine->delayed_tx_work,
					tipc_delayed_tx_worker);
		INIT_LIST_HEAD(&engine->not_retx_queue);
		INIT_DELAYED_WORK(&engine->cleanup_not_retx_work,
					tipc_cleanup_not_retx_worker);
		INIT_LIST_HEAD(&engine->retx_queue);
		engine->retx_iter = NULL;
		INIT_DELAYED_WORK(&engine->retx_work, tipc_retx_worker);

		INIT_DELAYED_WORK(&engine->reachable_work, tipc_reachable_node_worker);
		INIT_DELAYED_WORK(&engine->unreachable_work, tipc_unreachable_node_worker);
	}

	krgcom_wq = create_workqueue("krgcom");

	ack_cleanup_window_size = ACK_CLEANUP_WINDOW_SIZE;

	for (i = 0; i < KERRIGHED_MAX_NODES; i++) {
		max_consecutive_recv[i] = MAX_CONSECUTIVE_RECV;
	}

	tipc_net_id = kerrighed_session_id;

	lockdep_off();

	tipc_core_start_net(tipc_addr(1, 1, kerrighed_node_id+1));

	res = tipc_attach(&tipc_user_ref, NULL, NULL);
	if (res)
		goto exit_error;

	res = tipc_createport(tipc_user_ref, NULL, TIPC_LOW_IMPORTANCE,
			      NULL, NULL, NULL,
			      NULL, tipc_handler, NULL,
			      NULL, &tipc_port_ref);
	if (res)
		return res;

        tipc_seq.type = TIPC_KRG_SERVER_TYPE;
        tipc_seq.lower = tipc_seq.upper = kerrighed_node_id;
        res = tipc_publish(tipc_port_ref, TIPC_CLUSTER_SCOPE, &tipc_seq);

	for_each_possible_cpu(i){
		u32* send_ref = &per_cpu(tipc_send_ref, i);
		struct tipc_port* p;

		/* since TIPC do strange assumption regarding this field
		   we need to initialise it. But this field is dedicated
		   to the plugins of TIPC. ie: only our code use this field. So
		   we can set it to any value we want.
		*/
		p = tipc_createport_raw((void*)i,
					port_dispatcher, port_wakeup,
					TIPC_LOW_IMPORTANCE,
					(void*)0x1111);
		if(p){
			*send_ref = p->ref;
			spin_unlock_bh(p->lock);
		} else {
			spin_unlock_bh(p->lock);
			goto exit_error;
		}
	};

	lockdep_on();

	return 0;
	
 exit_error:
	printk("Error while trying to init TIPC (%d)\n", res);
        return res;
}
