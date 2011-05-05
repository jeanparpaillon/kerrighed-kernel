#ifndef __KRG_RPC__
#define __KRG_RPC__

#include <net/krgrpc/rpcid.h>
#include <kerrighed/krgnodemask.h>
#include <kerrighed/sys/types.h>

#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/kref.h>
#include <linux/errno.h>
#include <linux/sched.h>

struct rpc_connection;

#define RPC_DESC_TABLE_BITS 5
#define RPC_DESC_TABLE_SIZE (1 << RPC_DESC_TABLE_BITS)

struct rpc_communicator {
	unsigned long next_desc_id;
	struct hlist_head desc_clt[RPC_DESC_TABLE_SIZE];
	spinlock_t desc_clt_lock;
	struct rpc_connection *conn[KERRIGHED_MAX_NODES];
	unsigned long rpc_mask[(RPCID_MAX + BITS_PER_LONG - 1) / BITS_PER_LONG];
	struct kref kref;
	int id;
};

enum rpc_target {
	RPC_TARGET_NODE,
	RPC_TARGET_PIDTYPE,
};

enum rpc_handler {
	RPC_HANDLER_KTHREAD,
	RPC_HANDLER_KTHREAD_VOID,
	RPC_HANDLER_KTHREAD_INT,
	RPC_HANDLER_MAX
};

#define ESIGACK 542

enum {
	__RPC_FLAGS_NOBLOCK, /* request async operation */
	__RPC_FLAGS_EARLIER, /* do the action as soon as possible */
	__RPC_FLAGS_LATER,   /* do the action during the rpc_end_xxx */
	__RPC_FLAGS_SECURE,  /* force a copy of the sent buffer */
	__RPC_FLAGS_NOCOPY,  /* request the network buffer */
	__RPC_FLAGS_INTR,    /* sleep in INTERRUPTIBLE state */
	__RPC_FLAGS_REPOST,  /* post a send/recv without update seqid */
	__RPC_FLAGS_SIGACK,  /* unpack() should return SIGACKs */
	__RPC_FLAGS_MAX      /* Must be last */
};

#define RPC_FLAGS_NOBLOCK (1<<__RPC_FLAGS_NOBLOCK)
#define RPC_FLAGS_EARLIER (1<<__RPC_FLAGS_EARLIER)
#define RPC_FLAGS_LATER   (1<<__RPC_FLAGS_LATER)
#define RPC_FLAGS_SECURE  (1<<__RPC_FLAGS_SECURE)
#define RPC_FLAGS_NOCOPY  (1<<__RPC_FLAGS_NOCOPY)
#define RPC_FLAGS_INTR    (1<<__RPC_FLAGS_INTR)
#define RPC_FLAGS_REPOST  (1<<__RPC_FLAGS_REPOST)
#define RPC_FLAGS_SIGACK  (1<<__RPC_FLAGS_SIGACK)

enum rpc_rq_type {
	RPC_RQ_UNDEF,
	RPC_RQ_CLT,
	RPC_RQ_SRV,
	RPC_RQ_FWD,
};

enum {
	__RPC_STATE_NEW,
	__RPC_STATE_HANDLE,
	__RPC_STATE_RUN,
	__RPC_STATE_CANCEL,
	__RPC_STATE_END,
	__RPC_STATE_WAIT,
	__RPC_STATE_WAIT1,
};

enum rpc_rq_state {
	RPC_STATE_NEW    = (1<<__RPC_STATE_NEW),
	RPC_STATE_HANDLE = (1<<__RPC_STATE_HANDLE),
	RPC_STATE_RUN    = (1<<__RPC_STATE_RUN),
	RPC_STATE_CANCEL = (1<<__RPC_STATE_CANCEL),
	RPC_STATE_END    = (1<<__RPC_STATE_END),
	RPC_STATE_WAIT   = (1<<__RPC_STATE_WAIT),
	RPC_STATE_WAIT1  = (1<<__RPC_STATE_WAIT1),
};

#define RPC_STATE_MASK_VALID (RPC_STATE_RUN\
 | RPC_STATE_HANDLE \
 | RPC_STATE_NEW \
 | RPC_STATE_WAIT \
 | RPC_STATE_WAIT1)

struct rpc_connection_set;
struct rpc_service;

struct rpc_desc {
	struct rpc_desc_send* desc_send;
	struct rpc_desc_recv* desc_recv[KERRIGHED_MAX_NODES];
	struct rpc_communicator *comm;
	struct rpc_connection_set *conn_set;
	struct rpc_service* service;
	krgnodemask_t nodes;
	enum rpc_rq_type type;
	struct hlist_node list;
	spinlock_t *hash_lock;
	unsigned in_interrupt:1;
	unsigned forwarded:1;
	unsigned long desc_id;
	spinlock_t desc_lock;
	enum rpcid rpcid;
	kerrighed_node_t client;
	kerrighed_node_t server;
	unsigned long client_desc_id;
	enum rpc_rq_state state;
	struct task_struct *thread;
	kerrighed_node_t wait_from;
	atomic_t usage;
	struct __rpc_synchro *__synchro;
};

struct rpc_data {
	void *raw;
	void *data;
	size_t size;
};

typedef void (*rpc_handler_t) (struct rpc_desc* rpc_desc);

typedef void (*rpc_handler_void_t)(struct rpc_desc* rpc_desc,
				   void* data, size_t size);

typedef int (*rpc_handler_int_t) (struct rpc_desc* rpc_desc,
				  void* data, size_t size);

/*
 * RPC synchro
 */

struct rpc_synchro* rpc_synchro_new(int max,
				    char *label,
				    int order);

/*
 * RPC management
 */
int __rpc_register(enum rpcid rpcid,
		   enum rpc_target rpc_target,
		   enum rpc_handler rpc_handler,
		   struct rpc_synchro *rpc_synchro,
		   void* _h,
		   unsigned long flags);

struct rpc_desc* rpc_begin_m(enum rpcid rpcid,
			     struct rpc_communicator *comm,
			     krgnodemask_t* nodes);

int rpc_cancel(struct rpc_desc* desc);
int rpc_cancel_sync(struct rpc_desc *desc);

int rpc_pack(struct rpc_desc* desc, int flags, const void* data, size_t size);
int rpc_wait_pack(struct rpc_desc* desc, int seq_id);
int rpc_cancel_pack(struct rpc_desc* desc);

int rpc_forward(struct rpc_desc* desc, kerrighed_node_t node);

int rpc_unpack(struct rpc_desc* desc, int flags, void* data, size_t size);
int rpc_unpack_from(struct rpc_desc* desc, kerrighed_node_t node,
		    int flags, void* data, size_t size);
void rpc_cancel_unpack(struct rpc_desc* desc);

kerrighed_node_t rpc_check_return(struct rpc_desc *desc, int *value);
kerrighed_node_t rpc_wait_return(struct rpc_desc* desc, int* value);
int rpc_wait_all(struct rpc_desc *desc);

int rpc_signal(struct rpc_desc* desc, int sigid);

int rpc_end(struct rpc_desc *rpc_desc, int flags);

void rpc_free_buffer(struct rpc_data *buf);

s64 rpc_consumed_bytes(void);

void
rpc_enable_lowmem_mode(struct rpc_communicator *comm, kerrighed_node_t nodeid);
void
rpc_disable_lowmem_mode(struct rpc_communicator *comm, kerrighed_node_t nodeid);
void rpc_enable_local_lowmem_mode(struct rpc_communicator *comm);
void rpc_disable_local_lowmem_mode(struct rpc_communicator *comm);

/*
 * Convenient define
 */

#define rpc_pack_type(desc, v) rpc_pack(desc, 0, &v, sizeof(v))
#define rpc_unpack_type(desc, v) rpc_unpack(desc, 0, &v, sizeof(v))
#define rpc_unpack_type_from(desc, n, v) rpc_unpack_from(desc, n, 0, &v, sizeof(v))

/*
 * Convenient functions
 */

static inline
int rpc_register_void(enum rpcid rpcid,
		      rpc_handler_void_t h,
		      unsigned long flags){
	return __rpc_register(rpcid, RPC_TARGET_NODE, RPC_HANDLER_KTHREAD_VOID,
			      NULL, (rpc_handler_t)h, flags);
};

static inline
int rpc_register_int(enum rpcid rpcid,
		     rpc_handler_int_t h,
		     unsigned long flags){
	return __rpc_register(rpcid, RPC_TARGET_NODE, RPC_HANDLER_KTHREAD_INT,
			      NULL, (rpc_handler_t)h, flags);
};

static inline
int rpc_register(enum rpcid rpcid,
		 rpc_handler_t h,
		 unsigned long flags){
	return __rpc_register(rpcid, RPC_TARGET_NODE, RPC_HANDLER_KTHREAD,
			      NULL, h, flags);
};

static inline
struct rpc_desc* rpc_begin(enum rpcid rpcid,
			   struct rpc_communicator *comm,
			   kerrighed_node_t node){
	krgnodemask_t nodes;

	krgnodes_clear(nodes);
	krgnode_set(node, nodes);

	return rpc_begin_m(rpcid, comm, &nodes);
};

static inline
int rpc_async_m(enum rpcid rpcid,
		struct rpc_communicator *comm,
		krgnodemask_t* nodes,
		const void* data, size_t size){
	struct rpc_desc* desc;
	int err = -ENOMEM;

	desc = rpc_begin_m(rpcid, comm, nodes);
	if (!desc)
		goto out;

	err = rpc_pack(desc, 0, data, size);

	/* rpc_end() always succeeds without delayed rpc_pack() */
	rpc_end(desc, 0);

out:
	return err;
};

static inline
int rpc_async(enum rpcid rpcid,
	      struct rpc_communicator *comm,
	      kerrighed_node_t node,
	      const void* data, size_t size){
	krgnodemask_t nodes;

	krgnodes_clear(nodes);
	krgnode_set(node, nodes);
	
	return rpc_async_m(rpcid, comm, &nodes, data, size);
};

static inline
int rpc_sync_m(enum rpcid rpcid,
	       struct rpc_communicator *comm,
	       krgnodemask_t* nodes,
	       const void* data, size_t size){
	struct rpc_desc *desc;
	int rold, r, first, error;
	int i;

	r = -ENOMEM;
	desc = rpc_begin_m(rpcid, comm, nodes);
	if (!desc)
		goto out;

	r = rpc_pack(desc, 0, data, size);
	if (r)
		goto end;

	i = 0;
	first = 1;
	error = 0;
	r = 0;

	__for_each_krgnode_mask(i, nodes){
		rpc_unpack_type_from(desc, i, rold);
		if(first){
			r = rold;
			first = 0;
		}else
			error = error || (r != rold);
		i++;
	};

end:
	/* rpc_end() always succeeds without delayed rpc_pack() */
	rpc_end(desc, 0);

out:
	return r;
};

static inline
int rpc_sync(enum rpcid rpcid,
	     struct rpc_communicator *comm,
	     kerrighed_node_t node,
	     const void* data, size_t size){
	krgnodemask_t nodes;

	krgnodes_clear(nodes);
	krgnode_set(node, nodes);
	
	return rpc_sync_m(rpcid, comm, &nodes, data, size);
};

void rpc_enable(enum rpcid rpcid);
void rpc_enable_all(void);
void rpc_disable(enum rpcid rpcid);
void rpc_disable_all(void);

void rpc_enable_alldev(void);
int rpc_enable_dev(const char *name);
void rpc_disable_alldev(void);
int rpc_disable_dev(const char *name);

static inline void rpc_communicator_get(struct rpc_communicator *communicator)
{
	kref_get(&communicator->kref);
}
void rpc_communicator_release(struct kref *kref);
static inline
void rpc_communicator_put(struct rpc_communicator *communicator)
{
	kref_put(&communicator->kref, rpc_communicator_release);
}
struct rpc_communicator *rpc_find_get_communicator(int id);

int rpc_connect(struct rpc_communicator *comm, kerrighed_node_t node);
void rpc_close(struct rpc_communicator *comm, kerrighed_node_t node);

int rpc_connect_mask(struct rpc_communicator *comm, const krgnodemask_t *nodes);
void rpc_close_mask(struct rpc_communicator *comm, const krgnodemask_t *nodes);

kerrighed_node_t rpc_desc_get_client(struct rpc_desc *desc);

extern struct task_struct *first_krgrpc;
extern struct files_struct krgrpc_files;

static inline int is_krgrpc_thread(struct task_struct *task)
{
	return (task->files == &krgrpc_files);
}
#endif
