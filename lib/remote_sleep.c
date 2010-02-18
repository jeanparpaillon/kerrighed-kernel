/*
 *  lib/remote_sleep.c
 *
 *  Copyright (C) 2010 Louis Rilling - Kerlabs
 */
#include <linux/sched.h>
#include <linux/signal.h>
#include <linux/errno.h>
#include <net/krgrpc/rpc.h>

int remote_sleep_prepare(struct rpc_desc *desc)
{
	int dummy, err;

	current->sighand->action[SIGINT - 1].sa.sa_handler = SIG_DFL;
	err = rpc_pack_type(desc, dummy);
	if (err)
		ignore_signals(current);

	return err;
}

void remote_sleep_finish(void)
{
	ignore_signals(current);
}

int unpack_remote_sleep_res_prepare(struct rpc_desc *desc)
{
	int dummy, err;

	err = rpc_unpack_type(desc, dummy);
	if (err > 0)
		err = -EPIPE;
	return err;
}

/**
 *  Unpack the result value of a remote, sleepable, interruptible operation
 *  @author Renaud Lottiaux
 *
 *  @param desc		The RPC descriptor to get the result from.
 *  @param res		Pointer to store the result.
 *  @param size		Size of the result.
 *
 *  @return		0 in case of success, or negative error code.
 */
int unpack_remote_sleep_res(struct rpc_desc *desc, void *res, size_t size)
{
	int err, flags;

	flags = RPC_FLAGS_INTR;
	for (;;) {
		err = rpc_unpack(desc, flags, res, size);
		switch (err) {
			case RPC_EOK:
				return 0;
			case RPC_EINTR:
				BUG_ON(flags != RPC_FLAGS_INTR);
				rpc_signal(desc, SIGINT);
				/*
				 * We do not need to explicitly receive SIGACK,
				 * since the server will return the result
				 * anyway.
				 */
				flags = 0;
				break;
			case RPC_EPIPE:
				return -EPIPE;
			default:
				BUG();
		}
	}

	return err;
}
