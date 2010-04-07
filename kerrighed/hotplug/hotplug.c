/*
 *  Copyright (C) 2006-2007, Pascal Gallard, Kerlabs.
 */

#include <linux/notifier.h>
#include <linux/idr.h>
#include <linux/list.h>
#include <linux/workqueue.h>
#include <linux/completion.h>
#include <linux/cluster_barrier.h>
#include <linux/slab.h>

#include <kerrighed/hotplug.h>
#include <kerrighed/namespace.h>
#include <net/krgrpc/rpcid.h>
#include <net/krgrpc/rpc.h>

#include "hotplug_internal.h"

struct hotplug_request {
	struct list_head list;
	kerrighed_node_t node;
	int id;
};

DEFINE_MUTEX(hotplug_mutex);

struct workqueue_struct *krg_ha_wq;
static struct workqueue_struct *krg_hotplug_wq;

static DEFINE_IDR(local_hotplug_req_idr);

static LIST_HEAD(local_hotplug_req_list);
static DEFINE_MUTEX(local_hotplug_req_list_mutex);

static LIST_HEAD(global_hotplug_req_list);
static DEFINE_MUTEX(global_hotplug_req_list_mutex);

static kerrighed_node_t hotplug_coordinator;
static DEFINE_MUTEX(hotplug_coordinator_mutex);
static struct cluster_barrier *hotplug_coordinator_barrier;

struct hotplug_context *hotplug_ctx_alloc(struct krg_namespace *ns)
{
	struct hotplug_context *ctx;

	BUG_ON(!ns);
	ctx = kmalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return NULL;

	get_krg_ns(ns);
	ctx->ns = ns;
	init_completion(&ctx->ready);
	init_completion(&ctx->done);
	kref_init(&ctx->kref);

	return ctx;
}

void hotplug_ctx_release(struct kref *kref)
{
	struct hotplug_context *ctx;

	ctx = container_of(kref, struct hotplug_context, kref);
	put_krg_ns(ctx->ns);
	kfree(ctx);
}

int hotplug_queue_request(struct hotplug_context *ctx)
{
	int err;

	mutex_lock(&local_hotplug_req_list_mutex);

	err = -ENONET;
	if (!krgnode_online(kerrighed_node_id))
		goto unlock;

	err = 0;
	ctx->ret = 0;
	list_add_tail(&ctx->list, &local_hotplug_req_list);
	queue_work(krg_hotplug_wq, &ctx->work);

unlock:
	mutex_unlock(&local_hotplug_req_list_mutex);

	return err;
}

static int hotplug_dequeue_request(struct hotplug_context *ctx)
{
	mutex_lock(&local_hotplug_req_list_mutex);
	list_del(&ctx->list);
	mutex_unlock(&local_hotplug_req_list_mutex);

	return ctx->ret;
}

static void hotplug_cancel_all_requests(void)
{
	struct hotplug_context *ctx;

	mutex_lock(&local_hotplug_req_list_mutex);
	list_for_each_entry(ctx, &local_hotplug_req_list, list) {
		ctx->ret = -EINTR;
		complete(&ctx->done);
	}
	mutex_unlock(&local_hotplug_req_list_mutex);
}

struct hotplug_run_req_msg {
	int req_id;
};

static
void handle_hotplug_run_req(struct rpc_desc *desc, void *_msg, size_t size)
{
	struct hotplug_run_req_msg *msg = _msg;
	struct hotplug_context *ctx;

	rcu_read_lock();
	ctx = idr_find(&local_hotplug_req_idr, msg->req_id);
	rcu_read_unlock();
	BUG_ON(!ctx);

	ctx->ret = 0;
	complete(&ctx->ready);
}

static
int
hotplug_run_request(struct rpc_communicator *comm, struct hotplug_request *req)
{
	struct hotplug_run_req_msg msg;

	msg.req_id = req->id;
	return rpc_async(HOTPLUG_RUN_REQ, comm, req->node, &msg, sizeof(msg));
}

struct hotplug_start_req_msg {
	int req_id;
};

static
int handle_hotplug_start_req(struct rpc_desc *desc, void *_msg, size_t size)
{
	struct hotplug_start_req_msg *msg = _msg;
	struct hotplug_request *req;
	int err;

	err = -ENOMEM;
	req = kmalloc(sizeof(*req), GFP_KERNEL);
	if (!req)
		goto out;
	req->node = rpc_desc_get_client(desc);
	BUG_ON(req->node == KERRIGHED_NODE_ID_NONE);
	req->id = msg->req_id;

	mutex_lock(&global_hotplug_req_list_mutex);
	err = 0;
	if (list_empty(&global_hotplug_req_list))
		err = hotplug_run_request(desc->comm, req);
	if (!err)
		list_add_tail(&req->list, &global_hotplug_req_list);
	mutex_unlock(&global_hotplug_req_list_mutex);

	if (err)
		kfree(req);

out:
	return err;
}

int hotplug_start_request(struct hotplug_context *ctx)
{
	struct hotplug_start_req_msg msg;
	struct rpc_desc *desc;
	int err, ret;

	mutex_lock(&hotplug_coordinator_mutex);
	err = hotplug_dequeue_request(ctx);
	if (err)
		goto unlock;

	err = -ENOMEM;
	if (!idr_pre_get(&local_hotplug_req_idr, GFP_KERNEL))
		goto unlock;
	err = idr_get_new(&local_hotplug_req_idr, ctx, &ctx->id);
	if (err)
		goto unlock;

	err = -ENOMEM;
	desc = rpc_begin(HOTPLUG_START_REQ, ctx->ns->rpc_comm, hotplug_coordinator);
	if (!desc)
		goto out_check_err;
	msg.req_id = ctx->id;
	err = rpc_pack_type(desc, msg);
	if (err)
		goto out_end;
	err = rpc_unpack_type(desc, ret);
	if (err) {
		if (err > 0)
			err = -EPIPE;
		goto out_end;
	}
	if (ret)
		err = ret;
out_end:
	rpc_end(desc, 0);

out_check_err:
	if (err)
		idr_remove(&local_hotplug_req_idr, ctx->id);

unlock:
	mutex_unlock(&hotplug_coordinator_mutex);

	if (!err) {
		wait_for_completion(&ctx->ready);
		err = ctx->ret;
	}

	return err;
}

struct hotplug_finish_req_msg {
	int req_id;
};

static
int handle_hotplug_finish_req(struct rpc_desc *desc, void *_msg, size_t size)
{
	struct hotplug_finish_req_msg *msg = _msg;
	struct hotplug_request *req, *tmp;
	int err;

	mutex_lock(&global_hotplug_req_list_mutex);

	BUG_ON(list_empty(&global_hotplug_req_list));
	req = list_first_entry(&global_hotplug_req_list, struct hotplug_request, list);
	BUG_ON(req->node != rpc_desc_get_client(desc));
	BUG_ON(req->id != msg->req_id);
	list_del(&req->list);
	kfree(req);

	list_for_each_entry_safe(req, tmp, &global_hotplug_req_list, list) {
		if (!krgnode_online(req->node)) {
			list_del(&req->list);
			kfree(req);
			continue;
		}

		err = hotplug_run_request(desc->comm, req);
		if (err) {
			printk(KERN_WARNING "kerrighed: Could not run hotplug request from node %d! err = %d\n", req->node, err);
			printk(KERN_WARNING "kerrighed: Hotplug coordinator hung!\n");
		}
		break;
	}

	mutex_unlock(&global_hotplug_req_list_mutex);

	return 0;
}

void hotplug_finish_request(struct hotplug_context *ctx)
{
	struct hotplug_finish_req_msg msg;
	struct rpc_desc *desc;
	int err, ret;

	mutex_lock(&hotplug_coordinator_mutex);

	err = -ENOMEM;
	desc = rpc_begin(HOTPLUG_FINISH_REQ, ctx->ns->rpc_comm, hotplug_coordinator);
	if (!desc)
		goto unlock;
	msg.req_id = ctx->id;
	err = rpc_pack_type(desc, msg);
	if (err)
		goto out_end;
	rpc_unpack_type(desc, ret);

	idr_remove(&local_hotplug_req_idr, ctx->id);

out_end:
	rpc_end(desc, 0);

unlock:
	mutex_unlock(&hotplug_coordinator_mutex);

	if (err) {
		printk(KERN_WARNING "kerrighed: Could not notify hotplug coordinator: err = %d\n", err);
		printk(KERN_WARNING "kerrighed: Hotplug coordinator will probably hang!\n");
	}
}

static void handle_hotplug_coordinator_move(struct rpc_desc *desc)
{
	struct hotplug_request *req, tmp, *safe;
	int err;

	/*
	 * No need to lock the list, since all nodes have coordinator mutex
	 * locked, and thus none try to start/finish requests.
	 */
	BUG_ON(!list_empty(&global_hotplug_req_list));
	for (;;) {
		err = rpc_unpack_type(desc, tmp);
		if (err)
			goto cancel;
		if (tmp.node == KERRIGHED_NODE_ID_NONE)
			break;

		err = -ENOMEM;
		req = kmalloc(sizeof(*req), GFP_KERNEL);
		if (!req)
			goto error;
		*req = tmp;
		list_add_tail(&req->list, &global_hotplug_req_list);
	}

	if (rpc_pack_type(desc, err))
		goto cancel;
out:
	return;

cancel:
	rpc_cancel(desc);
	if (err > 0)
		err = -EPIPE;
error:
	list_for_each_entry_safe(req, safe, &global_hotplug_req_list, list) {
		list_del(&req->list);
		kfree(req);
	}
	goto out;
}

static
int
hotplug_coordinator_move(struct rpc_communicator *comm, kerrighed_node_t target)
{
	struct rpc_desc *desc;
	struct hotplug_request *req, *tmp;
	struct hotplug_request null_req;
	int err, ret;

	desc = rpc_begin(HOTPLUG_COORDINATOR_MOVE, comm, target);
	if (!desc)
		return -ENOMEM;

	/*
	 * No need to lock the list, since all nodes have coordinator mutex
	 * locked, and thus none try to start/finish requests.
	 */
	list_for_each_entry(req, &global_hotplug_req_list, list) {
		err = rpc_pack_type(desc, *req);
		if (err)
			goto cancel;
	}

	/* End of list mark */
	null_req = (struct hotplug_request) { .node = KERRIGHED_NODE_ID_NONE };
	err = rpc_pack_type(desc, null_req);
	if (err)
		goto cancel;

	err = rpc_unpack_type(desc, ret);
	if (err) {
		if (err > 0)
			err = -EPIPE;
	} else {
		err = ret;
	}
	if (err)
		goto out;

	list_for_each_entry_safe(req, tmp, &global_hotplug_req_list, list) {
		list_del(&req->list);
		kfree(req);
	}

out:
	return err;

cancel:
	rpc_cancel(desc);
	goto out;
}

static int hotplug_coordinator_reconfigure(struct hotplug_context *ctx,
					   const krgnodemask_t *new_map,
					   const krgnodemask_t *full_map)
{
	kerrighed_node_t new_coordinator;
	int err;

	new_coordinator = __first_krgnode(new_map);

	mutex_lock(&hotplug_coordinator_mutex);
	err = cluster_barrier(hotplug_coordinator_barrier, full_map, new_coordinator);
	if (err)
		goto unlock;

	if (hotplug_coordinator == kerrighed_node_id
	    && hotplug_coordinator != new_coordinator) {
		err = hotplug_coordinator_move(ctx->ns->rpc_comm, new_coordinator);
		if (err) {
			printk(KERN_ERR "kerrighed: Failed to move hotplug coordinator! Cluster reconfiguration hung!\n");
			goto unlock;
		}
	}
	hotplug_coordinator = new_coordinator;

	err = cluster_barrier(hotplug_coordinator_barrier, full_map, new_coordinator);
unlock:
	mutex_unlock(&hotplug_coordinator_mutex);

	return err;
}

static int hotplug_add(struct hotplug_context *ctx)
{
	krgnodemask_t new_map;

	rpc_enable(HOTPLUG_COORDINATOR_MOVE);

	krgnodes_or(new_map, krgnode_online_map, ctx->node_set.v);
	return hotplug_coordinator_reconfigure(ctx, &new_map, &new_map);
}

static int hotplug_remove_local(struct hotplug_context *ctx)
{
	krgnodemask_t old_map;

	hotplug_cancel_all_requests();

	if (!num_online_krgnodes())
		return 0;

	krgnodes_or(old_map, krgnode_online_map, ctx->node_set.v);
	return hotplug_coordinator_reconfigure(ctx, &krgnode_online_map, &old_map);
}

static int hotplug_remove_advert(struct hotplug_context *ctx)
{
	krgnodemask_t old_map;

	krgnodes_or(old_map, krgnode_online_map, ctx->node_set.v);
	return hotplug_coordinator_reconfigure(ctx, &krgnode_online_map, &old_map);
}

static
int
hotplug_notifier(struct notifier_block *nb, hotplug_event_t event, void *data)
{
	struct hotplug_context *ctx = data;
	int err;

	switch (event) {
	case HOTPLUG_NOTIFY_ADD:
		err = hotplug_add(ctx);
		break;
	case HOTPLUG_NOTIFY_REMOVE_LOCAL:
		err = hotplug_remove_local(ctx);
		break;
	case HOTPLUG_NOTIFY_REMOVE_ADVERT:
		err = hotplug_remove_advert(ctx);
		break;
	default:
		err = 0;
		break;
	}

	if (err)
		return notifier_from_errno(err);
	return NOTIFY_OK;
}

int init_hotplug(void)
{
	krg_ha_wq = create_workqueue("krgHA");
	BUG_ON(krg_ha_wq == NULL);

	krg_hotplug_wq = create_singlethread_workqueue("krg_hotplug");
	if (!krg_hotplug_wq)
		panic("kerrighed: Couldn't create hotplug workqueue!\n");

	hotplug_coordinator_barrier = alloc_cluster_barrier(HOTPLUG_COORDINATOR_BARRIER);
	if (IS_ERR(hotplug_coordinator_barrier))
		panic("kerrighed: Couldn't create hotplug coordinator barrier!\n");

	hotplug_hooks_init();

	hotplug_add_init();
#ifdef CONFIG_KRG_HOTPLUG_DEL
	hotplug_remove_init();
#endif
	hotplug_failure_init();
	hotplug_cluster_init();
	hotplug_namespace_init();
	hotplug_membership_init();

	rpc_register_int(HOTPLUG_START_REQ, handle_hotplug_start_req, 0);
	rpc_register_int(HOTPLUG_FINISH_REQ, handle_hotplug_finish_req, 0);
	rpc_register_void(HOTPLUG_RUN_REQ, handle_hotplug_run_req, 0);
	rpc_register(HOTPLUG_COORDINATOR_MOVE, handle_hotplug_coordinator_move, 0);

	register_hotplug_notifier(hotplug_notifier, HOTPLUG_PRIO_HOTPLUG_COORDINATOR);

	return 0;
};

void cleanup_hotplug(void)
{
};
