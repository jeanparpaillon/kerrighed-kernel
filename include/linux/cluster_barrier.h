/** Cluster wide barrier
 *  @file cluster_barrier.h
 *
 *  @author Renaud Lottiaux
 */
#include <linux/wait.h>
#include <linux/spinlock_types.h>
#include <kerrighed/krgnodemask.h>
#include <kerrighed/types.h>

enum static_cluster_barrier_id {
	CLUSTER_BARRIER_NONE = 0,
	HOTPLUG_COORDINATOR_BARRIER,
	KDDM_HOTPLUG_BARRIER,
	UNIQUE_ID_HOTPLUG_BARRIER,
	IPC_HOTPLUG_BARRIER,
	SCHED_HOTPLUG_BARRIER,
	ONLINE_HOTPLUG_BARRIER,
	CLUSTER_BARRIER_MAX,
};

struct cluster_barrier_core {
	krgnodemask_t nodes_in_barrier;
	krgnodemask_t nodes_to_wait;
	wait_queue_head_t waiting_tsk;
	int in_barrier;
};

struct cluster_barrier_id {
	unique_id_t key;
	int toggle;
};

struct cluster_barrier {
	spinlock_t lock;
	struct cluster_barrier_id id;
	struct cluster_barrier_core core[2];
};


struct cluster_barrier *alloc_cluster_barrier(unique_id_t key);
void free_cluster_barrier(struct cluster_barrier *barrier);
int cluster_barrier(struct cluster_barrier *barrier, const krgnodemask_t *nodes,
		    kerrighed_node_t master);
void init_cluster_barrier(void);

