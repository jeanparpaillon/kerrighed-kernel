/**
 *
 *  Copyright (C) 2007 Pascal Gallard, Kerlabs <Pascal.Gallard@kerlabs.com>
 *
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/smp.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/irqflags.h>
#include <linux/spinlock.h>
#include <linux/lockdep.h>
#include <linux/string.h>
#include <kerrighed/krgnodemask.h>

#include <net/krgrpc/rpcid.h>
#include <net/krgrpc/rpc.h>

#include "rpc_internal.h"

struct rpc_service** rpc_services;

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
		rpc_disable(i);
}

struct rpc_connection *
rpc_connection_alloc(struct rpc_communicator *comm, kerrighed_node_t node)
{
	struct rpc_connection *conn;
	int err;

	conn = rpc_connection_alloc_ll(comm, node);
	if (!conn)
		return NULL;

	rpc_desc_table_init(conn->desc_srv);
	conn->desc_done_id = 0;
	spin_lock_init(&conn->desc_done_lock);

	kref_init(&conn->kref);
	rpc_communicator_get(comm);
	conn->comm = comm;
	conn->peer = node;

	return conn;
}

void rpc_connection_release(struct kref *kref)
{
	struct rpc_communicator *comm;
	struct rpc_connection *conn;

	BUG();

	conn = container_of(kref, struct rpc_connection, kref);
	comm = conn->comm;
	rpc_connection_free_ll(conn);
	rpc_communicator_put(comm);
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
	struct rpc_connection *conn;

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
	for (i = 0; i < KERRIGHED_MAX_NODES; i++) {
		conn = rpc_connection_alloc(&static_communicator, i);
		if (!conn)
			panic("kerrighed: Couldn't allocate static"
			      "connection!\n");
		static_communicator.conn[i] = conn;
	}

	res = thread_pool_init();
	if(res)
		return res;
	
	res = comlayer_init();
	if(res)
		return res;

	res = rpclayer_init();
	if(res)
		return res;

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
