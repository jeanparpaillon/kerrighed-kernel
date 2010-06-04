/**
 *
 *  Copyright (C) 2007 Pascal Gallard, Kerlabs <Pascal.Gallard@kerlabs.com>
 *
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/completion.h>
#include <linux/workqueue.h>
#include <linux/smp.h>
#include <linux/rcupdate.h>
#include <linux/list.h>
#include <linux/idr.h>
#include <linux/slab.h>
#include <linux/irqflags.h>
#include <linux/hardirq.h>
#include <linux/spinlock.h>
#include <linux/lockdep.h>
#include <linux/string.h>
#include <kerrighed/krgnodemask.h>

#include <net/krgrpc/rpcid.h>
#include <net/krgrpc/rpc.h>

#include "rpc_internal.h"

struct rpc_service** rpc_services;

static DEFINE_IDR(rpc_conn_idr);
static DEFINE_SPINLOCK(rpc_conn_lock);
static DEFINE_SPINLOCK(rpc_comm_lock);
struct rpc_communicator static_communicator;

DEFINE_PER_CPU(struct hlist_head, rpc_desc_trash);

struct kmem_cache* rpc_desc_cachep;
struct kmem_cache* rpc_desc_send_cachep;
struct kmem_cache* rpc_desc_recv_cachep;
struct kmem_cache* rpc_desc_elem_cachep;
struct kmem_cache* rpc_tx_elem_cachep;
struct kmem_cache* __rpc_synchro_cachep;

/*
 * RPC management
 */
inline
struct rpc_service* rpc_service_init(enum rpcid rpcid,
				     enum rpc_target rpc_target,
				     enum rpc_handler rpc_handler,
				     struct rpc_synchro *rpc_synchro,
				     rpc_handler_t h,
				     unsigned long flags){
	struct rpc_service* service;

	service = kmalloc(sizeof(*service), GFP_KERNEL);
	if(!service){
		printk("OOM in rpc_service_init\n");
		return NULL;
	};
	
	service->id = rpcid;
	service->target = rpc_target;
	service->handler = rpc_handler;
	service->h = h;
	service->synchro = rpc_synchro;
	service->flags = flags;

	return service;
};

int __rpc_register(enum rpcid rpcid,
		   enum rpc_target rpc_target,
		   enum rpc_handler rpc_handler,
		   struct rpc_synchro *rpc_synchro,
		   void* _h, unsigned long flags){
	rpc_handler_t h = (rpc_handler_t)_h;
	rpc_services[rpcid] = rpc_service_init(rpcid, rpc_target, rpc_handler,
					       rpc_synchro, h, flags);

	rpc_disable(rpcid);
	return 0;
};

struct rpc_desc* rpc_desc_alloc(void){
	struct rpc_desc* desc;
	int in_interrupt;
	int cpu = smp_processor_id();
	
	in_interrupt = 0;
	if(hlist_empty(&per_cpu(rpc_desc_trash, cpu))){
		desc = kmem_cache_alloc(rpc_desc_cachep, GFP_ATOMIC);
		if(!desc)
			return NULL;
		
		in_interrupt = 1;
	}else{
		desc = container_of(per_cpu(rpc_desc_trash, cpu).first,
				    struct rpc_desc,
				    list);
		hlist_del(&desc->list);
	};

	memset(desc, 0, sizeof(*desc));
	spin_lock_init(&desc->desc_lock);
	desc->in_interrupt = in_interrupt;
	atomic_set(&desc->usage, 1);
	desc->__synchro = NULL;

	return desc;
};

void rpc_desc_get(struct rpc_desc* desc){
	BUG_ON(atomic_read(&desc->usage)==0);
	atomic_inc(&desc->usage);
};

void rpc_desc_put(struct rpc_desc* desc){
	BUG_ON(atomic_read(&desc->usage)==0);
	if(!atomic_dec_and_test(&desc->usage))
		return;
	
	kmem_cache_free(rpc_desc_cachep, desc);
};

struct rpc_desc_send* rpc_desc_send_alloc(void){
	struct rpc_desc_send* desc_send;

	desc_send = kmem_cache_alloc(rpc_desc_send_cachep, GFP_ATOMIC);
	if(!desc_send)
		return NULL;

	atomic_set(&desc_send->seq_id, 0);
	spin_lock_init(&desc_send->lock);
	INIT_LIST_HEAD(&desc_send->list_desc_head);
	desc_send->flags = 0;

	return desc_send;
};

struct rpc_desc_recv* rpc_desc_recv_alloc(void){
	struct rpc_desc_recv* desc_recv;

	desc_recv = kmem_cache_alloc(rpc_desc_recv_cachep, GFP_ATOMIC);
	if(!desc_recv)
		return NULL;

	atomic_set(&desc_recv->seq_id, 0);
	atomic_set(&desc_recv->nbunexpected, 0);
	INIT_LIST_HEAD(&desc_recv->list_desc_head);
	INIT_LIST_HEAD(&desc_recv->list_provided_head);
	INIT_LIST_HEAD(&desc_recv->list_signal_head);
	desc_recv->iter = NULL;
	desc_recv->iter_provided = NULL;
	desc_recv->received_packets = 0;
	desc_recv->flags = 0;
	
	return desc_recv;
};


void test(void){
}

/*
 *
 * Enable a registered RPC
 * We must take the waiting_desc_lock.
 * After each rpc handle, the krgrpc go through the waiting_desc
 * list, in order to find another desc to process. We must avoid
 * to enable an RPC when such iteration is happened
 *
 */
void rpc_enable(enum rpcid rpcid){
	spin_lock_bh(&waiting_desc_lock);
	if(rpc_services[rpcid]->id == rpcid)
		clear_bit(rpcid, static_communicator.rpc_mask);

	spin_unlock_bh(&waiting_desc_lock);
};

void rpc_enable_all(void){
	int i;

	for(i=0;i<RPCID_MAX;i++)
		rpc_enable(i);
	
	if(!list_empty(&waiting_desc))
		rpc_wake_up_thread(NULL);
};

void rpc_disable(enum rpcid rpcid){
	if(rpc_services[rpcid]->id == rpcid)
		set_bit(rpcid, static_communicator.rpc_mask);
};

void rpc_disable_all(void)
{
	int i;

	for(i = 0; i < RPCID_MAX; i++)
		if (i != RPC_CONNECT && i != RPC_CLOSE)
			rpc_disable(i);
}

static void rpc_connection_kill(struct work_struct *work);

int
rpc_connection_alloc(struct rpc_communicator *comm, kerrighed_node_t node)
{
	struct rpc_connection *conn;
	int err;

	err = -ENOMEM;
	conn = rpc_connection_alloc_ll(comm, node);
	if (!conn)
		return err;

	rpc_desc_table_init(conn->desc_srv);
	conn->desc_done_id = 0;
	spin_lock_init(&conn->desc_done_lock);

	/* Will be used by communicator and IDR table */
	kref_init(&conn->kref);
	kref_get(&conn->kref);
	rpc_communicator_get(comm);
	conn->comm = comm;
	conn->peer = node;
	conn->state = RPC_CONN_CLOSED;
	conn->connect_pending = 0;
	spin_lock_init(&conn->state_lock);
	init_completion(&conn->close_done);

	conn->peer_id = -1;

	for (;;) {
		err = -ENOMEM;
		if (!idr_pre_get(&rpc_conn_idr, GFP_ATOMIC))
			goto err_idr;

		spin_lock_bh(&rpc_comm_lock);

		err = -EBUSY;
		if (comm->conn[node])
			goto unlock;

		spin_lock(&rpc_conn_lock);
		err = idr_get_new(&rpc_conn_idr, conn, &conn->id);
		spin_unlock(&rpc_conn_lock);
		if (err)
			goto unlock;

		rcu_assign_pointer(comm->conn[node], conn);
		err = 0;

unlock:
		spin_unlock_bh(&rpc_comm_lock);

		if (err == -EAGAIN)
			continue;
		if (err)
			goto err_idr;
		break;
	}

	return err;

err_idr:
	rpc_connection_free_ll(conn);
	rpc_communicator_put(comm);
	return err;
}

static void rpc_connection_invalidate(struct rpc_connection *conn)
{
	struct rpc_communicator *comm = conn->comm;
	kerrighed_node_t node = conn->peer;

	/* Make conn an inactive connection */
	spin_lock_bh(&rpc_comm_lock);
	BUG_ON(comm->conn[node] != conn);
	rcu_assign_pointer(comm->conn[node], NULL);
	spin_unlock_bh(&rpc_comm_lock);
	rpc_connection_put(conn);
}

static void rpc_connection_free(struct rcu_head *rcu)
{
	struct rpc_communicator *comm;
	struct rpc_connection *conn;

	conn = container_of(rcu, struct rpc_connection, rcu);

	comm = conn->comm;
	rpc_connection_free_ll(conn);
	rpc_communicator_put(comm);
}

void rpc_connection_release(struct kref *kref)
{
	struct rpc_connection *conn;

	conn = container_of(kref, struct rpc_connection, kref);

	BUG_ON(conn->comm->conn[conn->peer] == conn);

	call_rcu(&conn->rcu, rpc_connection_free);
}

static inline bool rpc_connection_try_get(struct rpc_connection *conn)
{
	return atomic_add_unless(&conn->kref.refcount, 1, 0);
}

struct rpc_connection *rpc_find_get_connection(int id)
{
	struct rpc_connection *conn;

	rcu_read_lock();
	conn = idr_find(&rpc_conn_idr, id);
	if (conn && !rpc_connection_try_get(conn))
		conn = NULL;
	rcu_read_unlock();

	return conn;
}

struct rpc_connection *
rpc_communicator_get_connection(struct rpc_communicator *comm,
				kerrighed_node_t node)
{
	struct rpc_connection *conn;

	rcu_read_lock();
	conn = rcu_dereference(comm->conn[node]);
	if (conn && !rpc_connection_try_get(conn))
		conn = NULL;
	rcu_read_unlock();

	return conn;
}

struct rpc_connection_set *__rpc_connection_set_alloc(void)
{
	struct rpc_connection_set *set;

	set = kzalloc(sizeof(*set), GFP_ATOMIC);
	if (!set)
		return NULL;

	kref_init(&set->kref);

	return set;
}

struct rpc_connection_set *
rpc_connection_set_alloc(struct rpc_communicator *comm,
			 const krgnodemask_t *nodes)
{
	struct rpc_connection_set *set;
	kerrighed_node_t node;

	set = __rpc_connection_set_alloc();
	if (!set)
		return ERR_PTR(-ENOMEM);

	__for_each_krgnode_mask(node, nodes) {
		set->conn[node] = rpc_communicator_get_connection(comm, node);
		if (!set->conn[node])
			goto err_invalid_node;
	}

	return set;

err_invalid_node:
	__for_each_krgnode_mask(node, nodes)
		if (set->conn[node])
			rpc_connection_put(set->conn[node]);
	kfree(set);
	return ERR_PTR(-EPIPE);
}

void rpc_connection_set_release(struct kref *kref)
{
	struct rpc_connection_set *set;
	kerrighed_node_t node;

	set = container_of(kref, struct rpc_connection_set, kref);
	for (node = 0; node < KERRIGHED_MAX_NODES; node++)
		if (set->conn[node])
			rpc_connection_put(set->conn[node]);
	kfree(set);
}

int rpc_communicator_init(struct rpc_communicator *communicator, int id)
{
	memset(communicator, 0, sizeof(*communicator));
	communicator->next_desc_id = 1;
	rpc_desc_table_init(communicator->desc_clt);
	spin_lock_init(&communicator->desc_clt_lock);
	kref_init(&communicator->kref);
	communicator->id = id;
	return 0;
}

void rpc_communicator_release(struct kref *kref)
{
	struct rpc_communicator *communicator;

	BUG();
	communicator = container_of(kref, struct rpc_communicator, kref);
}

struct rpc_communicator *rpc_find_get_communicator(int id)
{
	BUG_ON(id != 0);

	kref_get(&static_communicator.kref);
	return &static_communicator;
}

static void rpc_connection_schedule_kill(struct rpc_connection *conn)
{
	INIT_DELAYED_WORK(&conn->kill_work, rpc_connection_kill);
	schedule_delayed_work(&conn->kill_work, 2 * RPC_MAX_TTL);
}

static void rpc_connection_delayed_time_wait(struct work_struct *work)
{
	struct rpc_connection *conn;

	conn = container_of(to_delayed_work(work), struct rpc_connection, kill_work);

	spin_lock_bh(&conn->state_lock);
	BUG_ON(conn->state != RPC_CONN_CLOSING);
	conn->state = RPC_CONN_TIME_WAIT;
	spin_unlock_bh(&conn->state_lock);

	rpc_connection_schedule_kill(conn);
}

/* Requires conn->state_lock held */
static void rpc_connection_check_abort(struct rpc_connection *conn, bool delay)
{
	if (conn->state != RPC_CONN_CLOSED || conn->connect_pending)
		return;

	rpc_connection_invalidate(conn);
	if (delay) {
		conn->state = RPC_CONN_CLOSING;
		INIT_DELAYED_WORK(&conn->kill_work, rpc_connection_delayed_time_wait);
		schedule_delayed_work(&conn->kill_work, 2 * RPC_MAX_TTL);
	} else {
		conn->state = RPC_CONN_TIME_WAIT;
		rpc_connection_schedule_kill(conn);
	}
}

/* Called in softirq context */
struct rpc_connection *rpc_handle_new_connection(kerrighed_node_t node,
						 int peer_id,
						 const struct rpc_connect_msg *msg)
{
	struct rpc_communicator *comm;
	struct rpc_connection *conn;
	bool new;
	int err;

	comm = rpc_find_get_communicator(msg->comm_id);
	BUG_ON(!comm);

	conn = rpc_communicator_get_connection(comm, node);
	if (!conn) {
		err = rpc_connection_alloc(comm, node);
		if (!err || err == -EBUSY)
			conn = rpc_communicator_get_connection(comm, node);
		else
			conn = NULL;
		if (!conn)
			goto out;
	}

	spin_lock(&conn->state_lock);
	new = conn->peer_id == -1 && conn->state != RPC_CONN_TIME_WAIT;
	if (new) {
		BUG_ON(conn->state != RPC_CONN_CLOSED
		       && conn->state != RPC_CONN_SYNSENT);
		conn->peer_id = peer_id;
		conn->connect_pending = 1;
	}
	spin_unlock(&conn->state_lock);
	if (!new && conn->peer_id != peer_id) {
		/*
		 * Aborted connection, very old duplicate packet,
		 * or early reconnection
		 */
		rpc_connection_put(conn);
		conn = NULL;
	}

out:
	rpc_communicator_put(comm);

	return conn;
}

/* Called in softirq context */
int rpc_handle_complete_connection(struct rpc_connection *conn, int peer_id)
{
	int err = -EINVAL;

	spin_lock(&conn->state_lock);
	if (conn->peer_id == -1 && conn->state != RPC_CONN_TIME_WAIT) {
		BUG_ON(conn->state != RPC_CONN_SYNSENT);
		conn->peer_id = peer_id;
		err = 0;
	}
	/* else if (conn->peer_id == -1 && conn->state == RPC_CONN_TIME_WAIT)
		Aborted connection
	   else if (conn->peer_id != peer_id)
		Very old duplicate packet!
	   else duplicate packet */
	spin_unlock(&conn->state_lock);

	return err;
}

static void handle_connect(struct rpc_desc *desc, void *msg, size_t size)
{
	struct rpc_connection *conn = desc->conn_set->conn[desc->client];
	int err;

	spin_lock_bh(&conn->state_lock);
	conn->connect_pending = 0;
	err = -EINVAL;
	if (conn->state <= RPC_CONN_ESTABLISHED)
		err = rpc_pack(desc, 0, NULL, 0);
	if (err) {
		rpc_cancel(desc);
		rpc_connection_check_abort(conn, true);
	} else if (conn->state == RPC_CONN_CLOSED) {
		conn->state = RPC_CONN_ESTABLISHED_AUTOCLOSE;
	} else if (conn->state == RPC_CONN_SYNSENT) {
		conn->state = RPC_CONN_ESTABLISHED;
	}
	spin_unlock_bh(&conn->state_lock);
}

int rpc_connect(struct rpc_communicator *comm, kerrighed_node_t node)
{
	struct rpc_connect_msg msg;
	struct rpc_connection *conn;
	struct rpc_desc *desc;
	bool do_close = false;
	int err;

	err = rpc_connection_alloc(comm, node);
	if (err && err != -EBUSY)
		return err;

	desc = rpc_begin(RPC_CONNECT, comm, node);
	if (!desc) {
		conn = rpc_communicator_get_connection(comm, node);
		if (conn) {
			spin_lock_bh(&conn->state_lock);
			rpc_connection_check_abort(conn, false);
			spin_unlock_bh(&conn->state_lock);
			rpc_connection_put(conn);
		}
		return -ENOMEM;
	}
	conn = desc->conn_set->conn[node];
	rpc_connection_get(conn);

	spin_lock_bh(&conn->state_lock);

	switch (conn->state) {
	case RPC_CONN_CLOSED:
		msg.comm_id = comm->id;
		err = rpc_pack_type(desc, msg);
		if (!err)
			conn->state = RPC_CONN_SYNSENT;
		else
			rpc_connection_check_abort(conn, false);
		spin_unlock_bh(&conn->state_lock);
		if (err)
			goto out_end;
		break;
	case RPC_CONN_ESTABLISHED_AUTOCLOSE:
		conn->state = RPC_CONN_ESTABLISHED;
		/* Fallthrough */
	case RPC_CONN_ESTABLISHED:
		spin_unlock_bh(&conn->state_lock);
		err = 0;
		goto out_end;
	case RPC_CONN_AUTOCLOSING:
	case RPC_CONN_CLOSE_WAIT:
	case RPC_CONN_LAST_ACK:
	case RPC_CONN_TIME_WAIT:
		/* Auto-closing, already existing connection */
		err = -EAGAIN;
		spin_unlock_bh(&conn->state_lock);
		goto out_end;
	default:
		BUG();
	}

	err = rpc_unpack(desc, 0, NULL, 0);
	if (err > 0)
		err = -EPIPE;

	spin_lock_bh(&conn->state_lock);

	if (err) {
		switch (conn->state) {
		case RPC_CONN_SYNSENT:
			conn->state = RPC_CONN_CLOSED;
			rpc_connection_check_abort(conn, false);
			break;
		case RPC_CONN_ESTABLISHED:
			err = 0;
			break;
		case RPC_CONN_CLOSE_WAIT:
			do_close = true;
			break;
		default:
			BUG();
		}
		goto out_unlock;
	}

	switch (conn->state) {
	case RPC_CONN_SYNSENT:
		conn->state = RPC_CONN_ESTABLISHED;
		/* Fallthrough */
	case RPC_CONN_ESTABLISHED:
		break;
	case RPC_CONN_CLOSE_WAIT:
		do_close = true;
		err = -EAGAIN;
		break;
	default:
		BUG();
	}

out_unlock:
	spin_unlock_bh(&conn->state_lock);

out_end:
	rpc_end(desc, 0);

	if (do_close)
		rpc_close(comm, conn->peer);
	rpc_connection_put(conn);

	return err;
}

static void rpc_connection_cancel_descs(struct rpc_connection *conn)
{
	struct rpc_communicator *comm = conn->comm;
	struct rpc_desc *desc;

	spin_lock_bh(&comm->desc_clt_lock);
	do_each_desc(desc, comm->desc_clt) {
		if (desc->rpcid != RPC_CLOSE
		    && desc->conn_set->conn[conn->peer_id] == conn)
			rpc_desc_cancel_wait(desc, conn->peer_id);
	} while_each_desc(desc, comm->desc_clt);
	spin_unlock_bh(&comm->desc_clt_lock);

	spin_lock_bh(&conn->desc_done_lock);
	do_each_desc(desc, conn->desc_srv) {
		rpc_desc_cancel_wait(desc, 0);
	} while_each_desc(desc, conn->desc_srv);
	spin_unlock_bh(&conn->desc_done_lock);
}

static void rpc_connection_kill(struct work_struct *work)
{
	struct rpc_connection *conn;

	conn = container_of(to_delayed_work(work), struct rpc_connection, kill_work);

	spin_lock_bh(&rpc_conn_lock);
	idr_remove(&rpc_conn_idr, conn->id);
	spin_unlock_bh(&rpc_conn_lock);

	rpc_connection_kill_ll(conn);
	rpc_connection_put(conn);
}

/* Called in softirq context */
int rpc_connection_check_state(struct rpc_connection *conn, enum rpcid rpcid)
{
	if (rpcid == RPC_CONNECT)
		return 0;

	if (rpcid == RPC_CLOSE) {
		spin_lock(&conn->state_lock);
		if (conn->state == RPC_CONN_ESTABLISHED_AUTOCLOSE)
			conn->state = RPC_CONN_AUTOCLOSING;
		spin_unlock(&conn->state_lock);
		return 0;
	}

	if (conn->state > RPC_CONN_ESTABLISHED)
		return -EPIPE;

	return 0;
}

/* Can be called in softirq context */
void rpc_connection_last_ack(struct rpc_connection *conn)
{
	spin_lock_bh(&conn->state_lock);
	switch (conn->state) {
	case RPC_CONN_FIN_WAIT_2:
		conn->state = RPC_CONN_TIME_WAIT;
		complete(&conn->close_done);
		break;
	case RPC_CONN_CLOSING:
	case RPC_CONN_CLOSE_WAIT:
	case RPC_CONN_LAST_ACK:
	case RPC_CONN_TIME_WAIT:
		break;
	default:
		BUG();
	}
	spin_unlock_bh(&conn->state_lock);
}

static void rpc_connection_close_timeout(struct work_struct *work)
{
	struct rpc_connection *conn;

	conn = container_of(to_delayed_work(work), struct rpc_connection, timeout_work);
	rpc_connection_last_ack(conn);
	rpc_connection_put(conn);
}

static void handle_close(struct rpc_desc *desc, void *msg, size_t size)
{
	struct rpc_connection *conn = desc->conn_set->conn[desc->client];
	bool do_autoclose = false, do_cancel_descs = false;
	int err;

	spin_lock_bh(&conn->state_lock);
	do {
		switch (conn->state) {
		case RPC_CONN_ESTABLISHED:
		case RPC_CONN_AUTOCLOSING:
		case RPC_CONN_FIN_WAIT_1:
		case RPC_CONN_FIN_WAIT_2:
			err = rpc_pack(desc, 0, NULL, 0);
			if (err) {
				spin_unlock_bh(&conn->state_lock);
				__set_current_state(TASK_UNINTERRUPTIBLE);
				schedule_timeout(HZ);
				spin_lock_bh(&conn->state_lock);
			}
			break;
		default:
			BUG();
		}
	} while (err);
	switch (conn->state) {
	case RPC_CONN_AUTOCLOSING:
		do_autoclose = true;
	case RPC_CONN_ESTABLISHED:
		conn->state = RPC_CONN_CLOSE_WAIT;
		if (!do_autoclose)
			do_cancel_descs = true;
		break;
	case RPC_CONN_FIN_WAIT_1:
		conn->state = RPC_CONN_CLOSING;
		break;
	case RPC_CONN_FIN_WAIT_2:
		rpc_connection_get(conn);
		INIT_DELAYED_WORK(&conn->timeout_work, rpc_connection_close_timeout);
		schedule_delayed_work(&conn->timeout_work, 2 * RPC_MAX_TTL);
		break;
	default:
		BUG();
	}
	spin_unlock_bh(&conn->state_lock);

	if (do_cancel_descs)
		rpc_connection_cancel_descs(conn);
	if (do_autoclose)
		rpc_close(conn->comm, conn->peer);
}

void rpc_close(struct rpc_communicator *comm, kerrighed_node_t node)
{
	struct rpc_connection *conn, *tmp_conn;
	struct rpc_desc *desc;
	int err;

	conn = rpc_communicator_get_connection(comm, node);
	BUG_ON(!conn);

	while (!(desc = rpc_begin(RPC_CLOSE, comm, node))) {
		/*
		 * In case of concurrent rpc_close(),
		 * rpc_begin() may fail because conn is no longer an active
		 * connection (ie no longer in the communicator).
		 * But we forbid concurrent rpc_close()!
		 */
		tmp_conn = rpc_communicator_get_connection(comm, node);
		BUG_ON(tmp_conn != conn);
		rpc_connection_put(tmp_conn);

		__set_current_state(TASK_UNINTERRUPTIBLE);
		schedule_timeout(HZ);
	}
	/* Concurrent rpc_close() are forbidden! */
	BUG_ON(conn != desc->conn_set->conn[node]);

	rpc_connection_invalidate(conn);

	spin_lock_bh(&conn->state_lock);

	do {
		switch (conn->state) {
		case RPC_CONN_ESTABLISHED:
		case RPC_CONN_CLOSE_WAIT:
			err = rpc_pack(desc, 0, NULL, 0);
			if (err) {
				spin_unlock_bh(&conn->state_lock);
				__set_current_state(TASK_UNINTERRUPTIBLE);
				schedule_timeout(HZ);
				spin_lock_bh(&conn->state_lock);
			}
			break;
		default:
			BUG();
		}
	} while (err);

	switch (conn->state) {
	case RPC_CONN_ESTABLISHED:
		conn->state = RPC_CONN_FIN_WAIT_1;
		break;
	case RPC_CONN_CLOSE_WAIT:
		conn->state = RPC_CONN_LAST_ACK;
		break;
	default:
		BUG();
	}

	spin_unlock_bh(&conn->state_lock);

	err = rpc_unpack(desc, 0, NULL, 0);
	rpc_end(desc, 0);

	spin_lock_bh(&conn->state_lock);

	if (err)
		goto zombify;

	switch (conn->state) {
	case RPC_CONN_FIN_WAIT_1:
		conn->state = RPC_CONN_FIN_WAIT_2;
		spin_unlock_bh(&conn->state_lock);
		wait_for_completion(&conn->close_done);
		goto kill;
	case RPC_CONN_CLOSING:
	case RPC_CONN_LAST_ACK:
		break;
	default:
		BUG();
	}

zombify:
	conn->state = RPC_CONN_TIME_WAIT;
	spin_unlock_bh(&conn->state_lock);

kill:
	rpc_connection_cancel_descs(conn);
	rpc_connection_schedule_kill(conn);
	rpc_connection_put(conn);
}

static
void __rpc_close_mask(struct rpc_communicator *comm, const krgnodemask_t *nodes,
		      kerrighed_node_t max_node)
{
	kerrighed_node_t node;

	__for_each_krgnode_mask(node, nodes) {
		if (node == max_node)
			break;
		rpc_close(comm, node);
	}
}

int rpc_connect_mask(struct rpc_communicator *comm, const krgnodemask_t *nodes)
{
	kerrighed_node_t node;
	int err = 0;

	__for_each_krgnode_mask(node, nodes) {
		err = rpc_connect(comm, node);
		if (err) {
			__rpc_close_mask(comm, nodes, node);
			break;
		}
	}

	return err;
}

void rpc_close_mask(struct rpc_communicator *comm, const krgnodemask_t *nodes)
{
	__rpc_close_mask(comm, nodes, KERRIGHED_MAX_NODES);
}

/** Initialisation of the rpc module.
 *  @author Pascal Gallard
 */

void rpc_undef_handler (struct rpc_desc *desc){
	printk("service %d not registered\n", desc->rpcid);
};

void rpc_enable_alldev(void)
{
	comlayer_enable();
}

int rpc_enable_dev(const char *name)
{
	return comlayer_enable_dev(name);
}

void rpc_disable_alldev(void)
{
	comlayer_disable();
}

int rpc_disable_dev(const char *name)
{
	return comlayer_disable_dev(name);
}

int init_rpc(void)
{
	int i, res;
	struct rpc_service *rpc_undef_service;

	rpc_desc_cachep = kmem_cache_create("rpc_desc",
					    sizeof(struct rpc_desc),
					    0, 0, NULL);
	if(!rpc_desc_cachep)
		return -ENOMEM;
	
	rpc_desc_send_cachep = kmem_cache_create("rpc_desc_send",
						 sizeof(struct rpc_desc_send),
						 0, 0, NULL);
	if(!rpc_desc_send_cachep)
		return -ENOMEM;

	rpc_desc_recv_cachep = kmem_cache_create("rpc_desc_recv",
						 sizeof(struct rpc_desc_recv),
						 0, 0, NULL);
	if(!rpc_desc_recv_cachep)
		return -ENOMEM;

	rpc_tx_elem_cachep = kmem_cache_create("rpc_tx_elem",
					       sizeof(struct rpc_tx_elem),
					       0, 0, NULL);
	if(!rpc_tx_elem_cachep)
		return -ENOMEM;

	rpc_desc_elem_cachep = kmem_cache_create("rpc_desc_elem",
						 sizeof(struct rpc_desc_elem),
						 0, 0, NULL);
	if(!rpc_desc_elem_cachep)
		return -ENOMEM;

	__rpc_synchro_cachep = kmem_cache_create("__rpc_synchro",
						 sizeof(struct __rpc_synchro),
						 0, 0, NULL);
	if(!__rpc_synchro_cachep)
		return -ENOMEM;
	
	rpc_services = kmalloc(sizeof(*rpc_services)*(RPCID_MAX+1),
			       GFP_KERNEL);
	if(!rpc_services)
		return -ENOMEM;

	rpc_undef_service = rpc_service_init(RPC_UNDEF,
					     RPC_TARGET_NODE,
					     RPC_HANDLER_KTHREAD_VOID,
					     NULL,
					     rpc_undef_handler, 0);

	for(i=0;i<RPCID_MAX;i++)
		rpc_services[i] = rpc_undef_service;
	
	for_each_possible_cpu(i){
		INIT_HLIST_HEAD(&per_cpu(rpc_desc_trash, i));
	};

	res = rpc_communicator_init(&static_communicator, 0);
	if (res)
		panic("kerrighed: Couldn't allocate static_communicator!\n");

	res = thread_pool_init();
	if(res)
		return res;
	
	res = comlayer_init();
	if(res)
		return res;

	res = rpclayer_init();
	if(res)
		return res;

	res = rpc_register_void(RPC_CONNECT, handle_connect, 0);
	if (res)
		return res;

	res = rpc_register_void(RPC_CLOSE, handle_close, 0);
	if (res)
		return res;

	rpc_enable(RPC_CONNECT);
	rpc_enable(RPC_CLOSE);

	/* res = rpc_monitor_init(); */
	/* if(res) */
	/*         return res; */
	
	printk("RPC initialisation done\n");
	
	return 0;
}

/** Cleanup of the Nazgul module.
 *  @author Pascal Gallard
 */
void cleanup_rpc(void)
{
}
