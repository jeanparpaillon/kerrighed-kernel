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
	int err;

	for_each_krgnode_mask(node, nodes) {
		err = rpc_unpack_type_from(desc, node, ret);
		if (err) /* unpack has failed */
			r = err;
		else if (ret)
			r = ret;
        }

	return r;
}

static inline int send_result(struct rpc_desc *desc, int result)
{
	int ret, err;

	err = rpc_pack_type(desc, result);
	if (err)
		goto err_rpc;
	err = rpc_unpack_type(desc, ret);
	if (err)
		goto err_rpc;

exit:
	return ret;
err_rpc:
	ret = err;
	goto exit;
}

static inline int ask_nodes_to_continue(struct rpc_desc *desc,
					krgnodemask_t nodes,
					int result)
{
	int err;

	err = rpc_pack_type(desc, result);
	if (err)
		goto exit;

	err = app_wait_returns_from_nodes(desc, nodes);
exit:
	return err;
}

struct task_struct *alloc_shared_fake_task_struct(struct app_struct *app);

void free_shared_fake_task_struct(struct task_struct *fake);

#endif /* __APP_UTILS_H__ */
