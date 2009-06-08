#ifndef __KRG_SCHEDULER_REMOTE_PIPE_H__
#define __KRG_SCHEDULER_REMOTE_PIPE_H__

#include <linux/workqueue.h>
#include <kerrighed/sys/types.h>

struct rpc_desc;

/*
 * Internal descriptor to hold the necessary state during an asynchronous
 * get_remote_value
 */
struct remote_pipe_desc {
	int pending;
	struct work_struct work;
	struct rpc_desc *desc;
	kerrighed_node_t node;
	void *value_p;
	int ret;
	spinlock_t lock;
};

struct scheduler_sink;
struct scheduler_pipe;

/**
 * Get the value of a remote globalized pipe source
 *
 * The request is asynchronous and non-blocking, which means that the call will
 * first return -EGAIN to notice the caller that the request is being
 * processed. The caller must retry later with the *same* parameters, until it
 * gets a result differing from -EAGAIN. If the calling sink provides an
 * update_value callback, it will be called once the result is available.
 *
 * Once a request is started, subsequent calls with different parameters will
 * return -EINVAL as long as the result is not retrieved by a call with the
 * parameters that started the request.
 *
 * The caller's sink must ensure that the array to get the values remains
 * available until the request finishes (result != -EAGAIN).
 *
 * @param sink		sink of the caller
 * @param local_pipe	local peer pipe of the remote pipe queried
 * @param node		node to get values from
 * @param value_p	array of values to be filled
 * @param nr		max number of values to fill
 * @param in_value_p	array of parameters, or NULL
 * @param in_nr		number of elements in in_value_p
 *
 * @return		number of values filled, or
 *			-EAGAIN if the results are not available yet, or
 *			other negative error code
 */
int scheduler_pipe_get_remote_value(
	struct scheduler_sink *sink,
	struct scheduler_pipe *local_pipe,
	kerrighed_node_t node,
	void *value_p, unsigned int nr,
	const void *in_value_p, unsigned int in_nr);

/**
 * Initialize the remote_pipe_desc embedded in a scheduler_sink
 *
 * @param sink		sink containing the remote_pipe_desc
 */
void scheduler_sink_remote_pipe_init(struct scheduler_sink *sink);
/**
 * Cleanup the remote_pipe_desc embedded in a scheduler_sink
 *
 * @param sink		sink containing the remote_pipe_desc
 */
static inline
void scheduler_sink_remote_pipe_cleanup(struct scheduler_sink *sink)
{
}

/**
 * Break any pending request to a remote scheduler_pipe
 * May block
 *
 * @param sink		sink containing the remote_pipe_desc
 */
void scheduler_sink_remote_pipe_disconnect(struct scheduler_sink *sink);

#endif /* __KRG_SCHEDULER_REMOTE_PIPE_H__ */
