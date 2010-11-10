#ifndef __KDDM_INTERNAL_H__
#define __KDDM_INTERNAL_H__

struct rpc_synchro;

extern struct rpc_synchro *kddm_server;
extern struct rpc_synchro *object_server;
extern struct rpc_synchro *object_server_may_block;

#endif /* __KDDM_INTERNAL_H__ */
