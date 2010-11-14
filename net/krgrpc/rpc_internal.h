#ifndef __RPC_INTERNAL__
#define __RPC_INTERNAL__

#include <linux/uio.h>
#include <linux/list.h>
#include <linux/hash.h>
#include <linux/spinlock.h>
#include <linux/radix-tree.h>
#include <linux/slab.h>
#include <linux/kref.h>
#include <kerrighed/sys/types.h>
#include <kerrighed/krgnodemask.h>
#include <net/krgrpc/rpc.h>

#define __RPC_HEADER_FLAGS_SIGNAL    (1<<0)
#define __RPC_HEADER_FLAGS_SIGACK    (1<<1)
#define __RPC_HEADER_FLAGS_SRV_REPLY (1<<3)
#define __RPC_HEADER_FLAGS_CANCEL_PACK (1<<4)
#define __RPC_HEADER_FLAGS_FORWARD   (1<<5)

enum {
	__RPC_FLAGS_EMERGENCY_BUF = __RPC_FLAGS_MAX,
	__RPC_FLAGS_NEW_DESC_ID,
	__RPC_FLAGS_CLOSED,
};

#define RPC_FLAGS_EMERGENCY_BUF	(1<<__RPC_FLAGS_EMERGENCY_BUF)
#define RPC_FLAGS_NEW_DESC_ID	(1<<__RPC_FLAGS_NEW_DESC_ID)
#define RPC_FLAGS_CLOSED	(1<<__RPC_FLAGS_CLOSED)

struct rpc_desc_send {
	atomic_t seq_id;
	spinlock_t lock;
	struct list_head list_desc_head;
	void *emergency_send_buf;
	int flags;
};

struct rpc_desc_recv {
	atomic_t seq_id;
	atomic_t nbunexpected;
	unsigned long received_packets;      // bitfield
	struct list_head list_desc_head;
	struct list_head list_provided_head;
	struct list_head list_signal_head;
	struct rpc_desc_elem *iter;
	struct rpc_desc_elem *iter_provided;
	int flags;
};

struct rpc_connection {
	struct hlist_head desc_srv[RPC_DESC_TABLE_SIZE];
	unsigned long desc_done_id;
	spinlock_t desc_done_lock;
	struct kref kref;
	struct rpc_communicator *comm;
	kerrighed_node_t peer;
};

struct __rpc_synchro_tree {
	spinlock_t lock;
	struct radix_tree_root rt;
};

enum ____rpc_synchro_flags {
	/* __rpc_synchro has been removed from its radix tree */
	____RPC_SYNCHRO_DEAD,
};

#define __RPC_SYNCHRO_DEAD (1<<____RPC_SYNCHRO_DEAD)

struct __rpc_synchro {
	atomic_t usage;
	atomic_t v;
	struct list_head list_waiting_head;
	spinlock_t lock;
	unsigned long key;
	struct __rpc_synchro_tree *tree;
	int flags;
};

struct rpc_synchro {
	int max;
	int order;
	unsigned long mask_packets;          // bitfield
	union {
		struct __rpc_synchro tab;
		struct __rpc_synchro_tree tree;
	} nodes[KERRIGHED_MAX_NODES];
	struct list_head list_synchro;
	char label[16];
};

struct rpc_service {
	enum rpc_target target;
	enum rpc_handler handler;
	rpc_handler_t h;
	struct rpc_synchro *synchro;
	enum rpcid id;
	unsigned long flags;
};

struct __rpc_header {
	kerrighed_node_t from;
	kerrighed_node_t client;
	kerrighed_node_t server;
	unsigned long desc_id;
	unsigned long client_desc_id;
	unsigned long seq_id;
	unsigned long link_seq_id;
	unsigned long link_ack_id;
	enum rpcid rpcid;
	int flags;
};

struct rpc_desc_elem {
	unsigned long seq_id;
	void* raw;
	void* data;
	size_t size;
	struct list_head list_desc_elem;
	int flags;
};

struct rpc_tx_elem {
	krgnodemask_t nodes;
	kerrighed_node_t index;
	kerrighed_node_t link_seq_index;
	void *data;
	struct iovec iov[2];
	struct __rpc_header h;
	unsigned long *link_seq_id;
	struct list_head tx_queue;
};

extern struct rpc_service** rpc_services;

extern struct kmem_cache* rpc_desc_cachep;
extern struct kmem_cache* rpc_desc_send_cachep;
extern struct kmem_cache* rpc_desc_recv_cachep;
extern struct kmem_cache* rpc_desc_elem_cachep;
extern struct kmem_cache* rpc_tx_elem_cachep;
extern struct kmem_cache* __rpc_synchro_cachep;

extern spinlock_t waiting_desc_lock;
extern struct list_head waiting_desc;

extern struct list_head list_synchro_head;

extern struct rpc_communicator static_communicator;

struct rpc_desc* rpc_desc_alloc(void);
struct rpc_desc_send* rpc_desc_send_alloc(void);
struct rpc_desc_recv* rpc_desc_recv_alloc(void);
void rpc_desc_elem_free(struct rpc_desc_elem *elem);

void rpc_desc_get(struct rpc_desc* desc);
void rpc_desc_put(struct rpc_desc* desc);

static inline int rpc_desc_hash_fn(unsigned long id)
{
	return hash_long(id, RPC_DESC_TABLE_BITS);
}

static inline
struct rpc_desc *rpc_desc_table_find(struct hlist_head *table, unsigned long id)
{
	struct hlist_head *head;
	struct rpc_desc *desc;
	struct hlist_node *node;

	head = &table[rpc_desc_hash_fn(id)];
	hlist_for_each_entry(desc, node, head, list)
		if (desc->desc_id == id)
			return desc;
	return NULL;
}

static inline
void rpc_desc_table_add(struct hlist_head *table, struct rpc_desc *desc)
{
	hlist_add_head(&desc->list, &table[rpc_desc_hash_fn(desc->desc_id)]);
}

static inline void rpc_desc_table_remove(struct rpc_desc *desc)
{
	hlist_del(&desc->list);
}

static inline void rpc_desc_table_init(struct hlist_head *table)
{
	int i;

	for (i = 0; i < RPC_DESC_TABLE_SIZE; i++)
		INIT_HLIST_HEAD(&table[i]);
}

void rpc_do_signal(struct rpc_desc *desc,
		   struct rpc_desc_elem *signal_elem);
void rpc_signal_deliver_pending(struct rpc_desc *desc,
				struct rpc_desc_recv *desc_recv);
int __rpc_signalack(struct rpc_desc* desc);

int rpc_handle_new(struct rpc_desc* desc);
void rpc_wake_up_thread(struct rpc_desc *desc);

void rpc_new_desc_id_lock(struct rpc_communicator *comm, bool lock_table);
void rpc_new_desc_id_unlock(struct rpc_communicator *comm, bool unlock_table);
int __rpc_emergency_send_buf_alloc(struct rpc_desc *desc, size_t size);
void __rpc_emergency_send_buf_free(struct rpc_desc *desc);
int __rpc_send_ll(struct rpc_desc* desc,
		  krgnodemask_t *nodes,
		  unsigned long seq_id,
		  int __flags,
		  const void* data, size_t size,
		  int rpc_flags);

void __rpc_put_raw_data(void *raw);
void __rpc_get_raw_data(void *raw);

struct rpc_connection *
rpc_connection_alloc_ll(struct rpc_communicator *comm, kerrighed_node_t node);
void rpc_connection_free_ll(struct rpc_connection *connection);

struct rpc_connection *
rpc_connection_alloc(struct rpc_communicator *comm, kerrighed_node_t node);

static inline void rpc_connection_get(struct rpc_connection *connection)
{
	kref_get(&connection->kref);
}

void rpc_connection_release(struct kref *kref);
static inline void rpc_connection_put(struct rpc_connection *connection)
{
	kref_put(&connection->kref, rpc_connection_release);
}

static inline struct rpc_connection *rpc_find_get_connection(int id)
{
	struct rpc_connection *conn = static_communicator.conn[id];

	rpc_connection_get(conn);
	return conn;
}

static
inline
struct rpc_connection *
rpc_communicator_get_connection(struct rpc_communicator *comm,
				kerrighed_node_t node)
{
	rpc_connection_get(comm->conn[node]);
	return comm->conn[node];
}

void __rpc_synchro_free(struct rpc_desc *desc);
int rpc_synchro_lookup(struct rpc_desc* desc);

int comlayer_init(void);
void comlayer_enable(void);
int comlayer_enable_dev(const char *name);
void comlayer_disable(void);
int comlayer_disable_dev(const char *name);
int thread_pool_init(void);
int rpclayer_init(void);
int rpc_monitor_init(void);

#endif

static inline bool rpc_desc_forwarded(struct rpc_desc *desc)
{
	return desc->forwarded;
}

static inline
int __rpc_synchro_get(struct __rpc_synchro *__rpc_synchro){
	return !atomic_inc_not_zero(&__rpc_synchro->usage);
}

static inline
void __rpc_synchro_put(struct __rpc_synchro *__rpc_synchro){

	if(!atomic_dec_and_test(&__rpc_synchro->usage))
		return;

	// Check if we are in a tree
	// If we are, we need to free the data
	if(__rpc_synchro->tree){
		spin_lock_bh(&__rpc_synchro->tree->lock);

		/* Maybe another CPU or a softIRQ had to replace __rpc_synchro
		 * in the radix tree (see rpc_synchro_lookup_order1())
		 */
		if (likely(!(__rpc_synchro->flags & __RPC_SYNCHRO_DEAD)))
			radix_tree_delete(&__rpc_synchro->tree->rt,
					  __rpc_synchro->key);

		spin_unlock_bh(&__rpc_synchro->tree->lock);

		kmem_cache_free(__rpc_synchro_cachep,
				__rpc_synchro);
	}
}
