/*
 *  kerrighed/scheduler/remote_pipe.c
 *
 *  Copyright (C) 2007-2008 Louis Rilling - Kerlabs
 *  Copyright (C) 2007 Marko Novak - Xlab
 */

#include <linux/kernel.h>
#include <linux/configfs.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <kerrighed/sys/types.h>
#include <kerrighed/krgnodemask.h>
#include <kerrighed/krginit.h>
#include <kerrighed/namespace.h>
#include <kerrighed/workqueue.h>
#include <kerrighed/hotplug.h>
#include <kerrighed/scheduler/pipe.h>
#include <kerrighed/scheduler/global_config.h>
#include <kerrighed/scheduler/remote_pipe.h>
#include <net/krgrpc/rpc.h>
#include <net/krgrpc/rpcid.h>

static void handle_pipe_get_remote_value(struct rpc_desc *desc)
{
	struct scheduler_pipe *pipe;
	struct scheduler_source *source;
	struct get_value_types *types;
	struct config_item *item;
	unsigned int nr, in_nr;
	void *value_p, *in_value_p;
	int ret;
	int err;

	item = global_config_unpack_get_item(desc);
	err = PTR_ERR(item);
	if (IS_ERR(item))
		goto err_cancel;
	pipe = to_scheduler_pipe(item);
	source = pipe->source;
	types = &scheduler_source_type_of(source)->get_value_types;
	err = rpc_unpack_type(desc, nr);
	if (err)
		goto err_put_item;
	err = rpc_unpack_type(desc, in_nr);
	if (err)
		goto err_put_item;
	err = -ENOMEM;
	value_p = NULL;
	if (nr) {
		value_p = kmalloc(nr * types->out_type_size, GFP_KERNEL);
		if (!value_p)
			goto err_put_item;
	}
	in_value_p = NULL;
	if (in_nr) {
		size_t in_size;
		in_size = in_nr * types->in_type_size;
		in_value_p = kmalloc(in_size, GFP_KERNEL);
		if (!in_value_p)
			goto err_free_value_p;
		err = rpc_unpack(desc, 0, in_value_p, in_size);
		if (err)
			goto err_free_in_value_p;
	}

	ret = scheduler_source_get_value(source, value_p, nr,
					 in_value_p, in_nr);

	err = rpc_pack_type(desc, ret);
	if (err)
		goto err_free_in_value_p;
	if (ret > 0) {
		err = rpc_pack(desc, 0,
			       value_p,
			       ret * types->out_type_size);
		if (err)
			goto err_free_in_value_p;
	}

	kfree(in_value_p);
	kfree(value_p);
	config_item_put(item);

	return;

err_free_in_value_p:
	kfree(in_value_p);
err_free_value_p:
	kfree(value_p);
err_put_item:
	config_item_put(item);
err_cancel:
	rpc_cancel(desc);
}

static void pipe_get_remote_value_worker(struct work_struct *work)
{
	struct remote_pipe_desc *show_desc =
		container_of(work, typeof(*show_desc), work);
	struct scheduler_sink *sink =
		container_of(show_desc, typeof(*sink), remote_pipe);
	size_t value_type_size = sink->type->get_value_types.out_type_size;
	int ret;
	int err;

	err = rpc_unpack_type(show_desc->desc, ret);
	if (err)
		goto err_cancel;
	show_desc->ret = ret;
	if (ret <= 0)
		goto end_request;
	err = rpc_unpack(show_desc->desc, 0,
			 show_desc->value_p, value_type_size * ret);
	if (err)
		goto err_cancel;

end_request:
	err = rpc_end(show_desc->desc, 0);

	membership_online_release();

	spin_lock(&show_desc->lock);
	show_desc->pending = 0;
	spin_unlock(&show_desc->lock);
	sink->type->update_value(sink, NULL);
	return;

err_cancel:
	rpc_cancel(show_desc->desc);
	if (err == -ECANCELED)
		err = -EPIPE;
	BUG_ON(err >= 0);
	show_desc->ret = err;
	goto end_request;
}

static int start_pipe_get_remote_value(
	struct scheduler_sink *sink,
	struct scheduler_pipe *local_pipe,
	kerrighed_node_t node,
	void *value_p, unsigned int nr,
	const void *in_value_p, unsigned int in_nr)
{
	struct remote_pipe_desc *show_desc = &sink->remote_pipe;
	struct krg_namespace *ns;
	struct rpc_desc *desc;
	size_t in_size = sink->type->get_value_types.in_type_size;
	int err;

	if (node == kerrighed_node_id)
		return scheduler_source_get_value(local_pipe->source,
						  value_p, nr,
						  in_value_p, in_nr);

	err = -EBUSY;
	if (!membership_online_try_hold())
		goto err;
	err = -EINVAL;
	if (!krgnode_online(node))
		goto err_not_online;

	err = -ENOMEM;
	ns = find_get_krg_ns();
	desc = rpc_begin(SCHED_PIPE_GET_REMOTE_VALUE, ns->rpc_comm, node);
	put_krg_ns(ns);
	if (!desc)
		goto err;
	err = global_config_pack_item(desc, &local_pipe->config.cg_item);
	if (err)
		goto err_cancel;
	err = rpc_pack_type(desc, nr);
	if (err)
		goto err_cancel;
	err = rpc_pack_type(desc, in_nr);
	if (err)
		goto err_cancel;
	if (in_nr) {
		err = rpc_pack(desc, 0, in_value_p, in_nr * in_size);
		if (err)
			goto err_cancel;
	}

	show_desc->pending = 1;
	show_desc->desc = desc;
	show_desc->node = node;
	show_desc->value_p = value_p;
	queue_work(krg_wq, &show_desc->work);
	return -EAGAIN;

err_cancel:
	rpc_cancel(desc);
	rpc_end(desc, 0);
err_not_online:
	membership_online_release();
err:
	BUG_ON(err == -EAGAIN);
	return err;
}

int scheduler_pipe_get_remote_value(
	struct scheduler_sink *sink,
	struct scheduler_pipe *local_pipe,
	kerrighed_node_t node,
	void *value_p, unsigned int nr,
	const void *in_value_p, unsigned int in_nr)
{
	struct remote_pipe_desc *show_desc = &sink->remote_pipe;
	int ret;

	if (!scheduler_source_type_of(local_pipe->source)->get_value)
		return -EACCES;
	if (!sink->type->update_value)
		return -EINVAL;
	if (!nr && !in_nr)
		return 0;
	if ((nr && !value_p) || (in_nr && !in_value_p))
		return -EINVAL;

	spin_lock(&show_desc->lock);
	if (show_desc->node != KERRIGHED_NODE_ID_NONE
	    && (show_desc->node != node
		|| show_desc->value_p != value_p)) {
		ret = -EINVAL;
	} else if (show_desc->pending) {
		ret = -EAGAIN;
	} else if (show_desc->node == KERRIGHED_NODE_ID_NONE) {
		/* Start a new asynchronous request */
		ret = start_pipe_get_remote_value(sink,
						  local_pipe,
						  node,
						  value_p, nr,
						  in_value_p, in_nr);
	} else {
		/* A result is ready and matches the current call. */
		show_desc->node = KERRIGHED_NODE_ID_NONE;
		ret = min((int) nr, show_desc->ret);
	}
	spin_unlock(&show_desc->lock);

	return ret;
}

void scheduler_sink_remote_pipe_init(struct scheduler_sink *sink)
{
	struct remote_pipe_desc *show_desc = &sink->remote_pipe;

	show_desc->pending = 0;
	INIT_WORK(&show_desc->work, pipe_get_remote_value_worker);
	show_desc->node = KERRIGHED_NODE_ID_NONE;
	spin_lock_init(&show_desc->lock);
}

void scheduler_sink_remote_pipe_disconnect(struct scheduler_sink *sink)
{
	/* Wait for (any) request worker to terminate */
	/*
	 * Lockdep warns against a possible circular locking dependency:
	 * (a)workqueue_mutex --> (a)kerrighed_init_sem --> (a)(b)mm->mmap_sem -->
	 * (b)(c)inode->i_mutex --> (c)workqueue_mutex, with (a) being called only once
	 * when creating kthreadd, (b) being called in sys_mmap(), and (c) being called
	 * in current path.
	 * Fortunately, the three chains do not happen to merge in any path :)
	 */
	lockdep_off();
	flush_workqueue(krg_wq);
	lockdep_on();
}

int remote_pipe_start(void)
{
	return rpc_register(SCHED_PIPE_GET_REMOTE_VALUE,
			    handle_pipe_get_remote_value, 0);
}

void remote_pipe_exit(void)
{
}
