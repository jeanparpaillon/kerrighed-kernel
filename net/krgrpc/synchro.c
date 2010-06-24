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

LIST_HEAD(list_synchro_head);

inline
void __rpc_synchro_init(struct __rpc_synchro *__rpc_synchro,
			int max){
	__rpc_synchro->key = 0;
	atomic_set(&__rpc_synchro->usage, 1);
	atomic_set(&__rpc_synchro->v, max);
	INIT_LIST_HEAD(&__rpc_synchro->list_waiting_head);
	spin_lock_init(&__rpc_synchro->lock);
	__rpc_synchro->tree = NULL;
	__rpc_synchro->flags = 0;
}

/*
 * RPC synchro
 */
struct rpc_synchro* rpc_synchro_new(int max,
				    char *label,
				    int order){
	struct rpc_synchro *ret;
	kerrighed_node_t i;

	ret = kmalloc(sizeof(*ret), GFP_KERNEL);
	BUG_ON(!ret);

	if(label)
		snprintf(ret->label, sizeof(ret->label), "%s", label);
	else
		snprintf(ret->label, sizeof(ret->label), "no name");

	ret->max = max;
	ret->order = order;

	ret->mask_packets = 0;
	for(i=0;i<ret->order;i++)
		set_bit(i, &ret->mask_packets);

	if(order){
		for(i=0;i<KERRIGHED_MAX_NODES;i++){
			INIT_RADIX_TREE(&ret->nodes[i].tree.rt, GFP_ATOMIC);
			spin_lock_init(&ret->nodes[i].tree.lock);
		}
	}else{
		for(i=0;i<KERRIGHED_MAX_NODES;i++)
			__rpc_synchro_init(&ret->nodes[i].tab, max);
	}

	list_add_tail(&ret->list_synchro, &list_synchro_head);
	return ret;
}

inline
int rpc_synchro_lookup_order0(struct rpc_desc *desc){
	__rpc_synchro_get(&desc->service->synchro->nodes[desc->client].tab);
	desc->__synchro = &desc->service->synchro->nodes[desc->client].tab;
	return 0;

};

inline
int rpc_synchro_lookup_order1(struct rpc_desc *desc){
	struct rpc_desc_elem *descelem;
	unsigned long key;
	struct rpc_synchro *synchro;
	struct __rpc_synchro *__synchro;
	struct __rpc_synchro_tree *__rpc_synchro_tree;

	synchro = desc->service->synchro;

	descelem = list_entry(desc->desc_recv[0]->list_desc_head.next,
			      struct rpc_desc_elem, list_desc_elem);

	key = *((unsigned long*)descelem->data);

	__rpc_synchro_tree = &synchro->nodes[desc->client].tree;

	spin_lock(&__rpc_synchro_tree->lock);
	__synchro = radix_tree_lookup(&__rpc_synchro_tree->rt, key);

	if(__synchro && __rpc_synchro_get(__synchro)) {
		/* __synchro is beeing freed. Just remove it from the tree and
		 * replace it with a clean new one. */
		radix_tree_delete(&__rpc_synchro_tree->rt, __synchro->key);
		__synchro->flags |= __RPC_SYNCHRO_DEAD;
		__synchro = NULL;
	}
	if (!__synchro){
		__synchro = kmem_cache_alloc(__rpc_synchro_cachep, GFP_ATOMIC);
		if(!__synchro){
			spin_unlock(&__rpc_synchro_tree->lock);
			return -ENOMEM;
		}

		__rpc_synchro_init(__synchro, synchro->max);

		__synchro->key = key;
		__synchro->tree = __rpc_synchro_tree;

		if (radix_tree_insert(&__rpc_synchro_tree->rt, key, __synchro)) {
			spin_unlock(&__rpc_synchro_tree->lock);
			kmem_cache_free(__rpc_synchro_cachep, __synchro);
			return -ENOMEM;
		}
	}
	spin_unlock(&__rpc_synchro_tree->lock);

	desc->__synchro = __synchro;

	return 0;
}

inline
int rpc_synchro_lookup_order_generic(struct rpc_desc *desc){
#if 0
	if((desc->desc_recv[0]->received_packets & desc->service->synchro->mask_packets)
	   == desc->service->synchro->mask_packets){
		desc->__synchro = &desc->service->synchro->nodes[desc->client];
		return 0;
	}

	return -ENOENT;
#endif

	printk("rpc_synchro_lookup: order > 1 => TODO\n");
	BUG();

	return 0;
}

int rpc_synchro_lookup(struct rpc_desc *desc){

	int order;

	if(!desc->service->synchro)
		return 0;

	order = desc->service->synchro->order;

	if(likely(order==0)){
		return rpc_synchro_lookup_order0(desc);
	}else if (likely(order==1)){
		return rpc_synchro_lookup_order1(desc);
	}else{
		return rpc_synchro_lookup_order_generic(desc);
	}
}
