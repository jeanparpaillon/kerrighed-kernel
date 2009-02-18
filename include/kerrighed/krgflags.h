#ifndef __KRGFLAGS_H__
#define __KRGFLAGS_H__

enum {
	__KRGFLAGS_LOADED,
	__KRGFLAGS_STARTING,
	__KRGFLAGS_RUNNING,
	__KRGFLAGS_ADDING,
	__KRGFLAGS_REMOVING,
	__KRGFLAGS_RECOVERING,
	__KRGFLAGS_STOPPING,
	__KRGFLAGS_STOPPED,
	__KRGFLAGS_FAILED,
};

#define KRGFLAGS_LOADED (1<<__KRGFLAGS_LOADED)
#define KRGFLAGS_STARTING (1<<__KRGFLAGS_STARTING)
#define KRGFLAGS_RUNNING (1<<__KRGFLAGS_RUNNING)
#define KRGFLAGS_ADDING (1<<__KRGFLAGS_ADDING)
#define KRGFLAGS_REMOVING (1<<__KRGFLAGS_REMOVING)
#define KRGFLAGS_RECOVERING (1<<__KRGFLAGS_RECOVERING)
#define KRGFLAGS_STOPPING (1<<__KRGFLAGS_STOPPING)
#define KRGFLAGS_STOPPED (1<<__KRGFLAGS_STOPPED)
#define KRGFLAGS_FAILED (1<<__KRGFLAGS_FAILED)

extern int kerrighed_cluster_flags;
extern int kerrighed_node_flags;

#define IS_KERRIGHED_CLUSTER(m) (kerrighed_cluster_flags & m)
#define IS_KERRIGHED_NODE(m) (kerrighed_node_flags & m)

#define SET_KERRIGHED_CLUSTER_FLAGS(m) kerrighed_cluster_flags |= m
#define SET_KERRIGHED_NODE_FLAGS(m) kerrighed_node_flags |= m

#define CLEAR_KERRIGHED_CLUSTER_FLAGS(m) kerrighed_cluster_flags &= ~m
#define CLEAR_KERRIGHED_NODE_FLAGS(m) kerrighed_node_flags &= ~m

#endif
