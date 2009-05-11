/*
 *  Kerrighed/modules/epm/app_utils.h
 *
 *  Copyright (C) 2008 INRIA
 *
 *  @author Matthieu Fertré
 */
#ifndef __APP_UTILS_H__
#define __APP_UTILS_H__

#include <net/krgrpc/rpc.h>

static inline int app_wait_returns_from_nodes(struct rpc_desc *desc,
					      krgnodemask_t nodes)
{
	kerrighed_node_t node;
	int ret, r=0;
	enum rpc_error error;

	for_each_krgnode_mask(node, nodes) {
		error = rpc_unpack_type_from(desc, node, ret);
		if (error) /* unpack has failed */
			r = error;
		else if (ret)
			r = ret;
        }

	return r;
}

static inline int send_result(struct rpc_desc *desc, int result)
{
	int r;
	enum rpc_error error;

	error = rpc_pack_type(desc, result);
	if (error)
		goto err_rpc;
	error = rpc_unpack_type(desc, r);
	if (error)
		goto err_rpc;

exit:
	return r;
err_rpc:
	r = error;
	goto exit;
}

static inline int ask_nodes_to_continue(struct rpc_desc *desc,
					krgnodemask_t nodes,
					int result)
{
	int r;
	enum rpc_error error;

	error = rpc_pack_type(desc, result);
	if (error)
		goto err_rpc;

	r = app_wait_returns_from_nodes(desc, nodes);
exit:
	return r;
err_rpc:
	r = error;
	goto exit;
}

#endif /* __APP_UTILS_H__ */
