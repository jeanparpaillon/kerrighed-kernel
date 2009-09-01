/*
 *  kerrighed/proc/remote_syscall.c
 *
 *  Copyright (C) 2009 Louis Rilling - Kerlabs
 */
#include <net/krgrpc/rpc.h>
#include <linux/cred.h>
#include <kerrighed/remote_cred.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>
#include <kerrighed/pid.h>
#include <kerrighed/hotplug.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <asm/current.h>

#include <kerrighed/remote_syscall.h>

static void *cluster_started;

struct remote_syscall_header {
	pid_t pid;
	size_t payload;
};

struct rpc_desc *krg_remote_syscall_begin(int req, pid_t pid,
					  const void *msg, size_t size)
{
	struct remote_syscall_header hdr;
	struct rpc_desc *desc;
	kerrighed_node_t node;
	int err = -ESRCH;

	if (!cluster_started)
		goto err;

	if (!current->nsproxy->krg_ns)
		goto err;

	if (!is_krg_pid_ns_root(task_active_pid_ns(current)))
		goto err;

	if (pid < 0 || !(pid & GLOBAL_PID_MASK))
		goto err;

	node = krg_lock_pid_location(pid);
	if (node == KERRIGHED_NODE_ID_NONE)
		goto err;

	err = -ENOMEM;
	desc = rpc_begin(req, node);
	if (!desc)
		goto err_unlock;

	hdr.pid = pid;
	hdr.payload = size;
	err = rpc_pack_type(desc, hdr);
	if (err)
		goto err_cancel;
	if (size) {
		err = rpc_pack(desc, 0, msg, size);
		if (err)
			goto err_cancel;
	}
	err = pack_creds(desc, current_cred());
	if (err)
		goto err_cancel;

	return desc;

err_cancel:
	rpc_cancel(desc);
	rpc_end(desc, 0);
err_unlock:
	krg_unlock_pid_location(pid);
err:
	return ERR_PTR(err);
}

void krg_remote_syscall_end(struct rpc_desc *desc, pid_t pid)
{
	rpc_end(desc, 0);
	krg_unlock_pid_location(pid);
}

int krg_remote_syscall_simple(int req, pid_t pid, const void *msg, size_t size)
{
	struct rpc_desc *desc;
	int ret, err;

	desc = krg_remote_syscall_begin(req, pid, msg, size);
	if (IS_ERR(desc)) {
		ret = PTR_ERR(desc);
		goto out;
	}
	err = rpc_unpack_type(desc, ret);
	if (err)
		ret = err;
	krg_remote_syscall_end(desc, pid);

out:
	return ret;
}

int krg_handle_remote_syscall_begin(struct rpc_desc *desc,
				    const void *_msg, size_t size,
				    void *msg,
				    const struct cred **old_cred)
{
	const struct remote_syscall_header *hdr = _msg;
	pid_t pid = hdr->pid;
	struct cred *cred;
	int ret;

	BUG_ON(task_active_pid_ns(current) != &init_pid_ns);

	if (hdr->payload) {
		ret = rpc_unpack(desc, 0, msg, hdr->payload);
		if (ret)
			goto err_cancel;
	}

	ret = -ENOMEM;
	cred = prepare_creds();
	if (!cred)
		goto err_cancel;
	ret = unpack_creds(desc, cred);
	if (ret) {
		put_cred(cred);
		goto err_cancel;
	}
	*old_cred = override_creds(cred);

	ret = pid;

out:
	return ret;

err_cancel:
	if (ret > 0)
		ret = -EPIPE;
	rpc_cancel(desc);
	goto out;
}

void krg_handle_remote_syscall_end(const struct cred *old_cred)
{
	const struct cred *cred = current_cred();

	revert_creds(old_cred);
	put_cred(cred);
}

void register_remote_syscalls_hooks(void)
{
	hook_register(&cluster_started, (void *)true);
}

void proc_remote_syscalls_start(void)
{
	remote_signals_init();
	remote_sched_init();
	remote_sys_init();
}
