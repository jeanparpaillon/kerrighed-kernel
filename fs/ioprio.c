/*
 * fs/ioprio.c
 *
 * Copyright (C) 2004 Jens Axboe <axboe@kernel.dk>
 *
 * Helper functions for setting/querying io priorities of processes. The
 * system calls closely mimmick getpriority/setpriority, see the man page for
 * those. The prio argument is a composite of prio class and prio data, where
 * the data argument has meaning within that class. The standard scheduling
 * classes have 8 distinct prio levels, with 0 being the highest prio and 7
 * being the lowest.
 *
 * IOW, setting BE scheduling class with prio 2 is done ala:
 *
 * unsigned int prio = (IOPRIO_CLASS_BE << IOPRIO_CLASS_SHIFT) | 2;
 *
 * ioprio_set(PRIO_PROCESS, pid, prio);
 *
 * See also Documentation/block/ioprio.txt
 *
 */
#include <linux/kernel.h>
#include <linux/ioprio.h>
#include <linux/blkdev.h>
#include <linux/capability.h>
#include <linux/syscalls.h>
#include <linux/security.h>
#include <linux/pid_namespace.h>
#ifdef CONFIG_KRG_PROC
#include <linux/pid_namespace.h>
#include <net/krgrpc/rpc.h>
#include <net/krgrpc/rpcid.h>
#include <kerrighed/pid.h>
#include <kerrighed/remote_cred.h>
#include <kerrighed/remote_syscall.h>
#endif

int set_task_ioprio(struct task_struct *task, int ioprio)
{
	int err;
	struct io_context *ioc;
	const struct cred *cred = current_cred(), *tcred;

	rcu_read_lock();
	tcred = __task_cred(task);
	if (tcred->uid != cred->euid &&
	    tcred->uid != cred->uid && !capable(CAP_SYS_NICE)) {
		rcu_read_unlock();
		return -EPERM;
	}
	rcu_read_unlock();

	err = security_task_setioprio(task, ioprio);
	if (err)
		return err;

	task_lock(task);
	do {
		ioc = task->io_context;
		/* see wmb() in current_io_context() */
		smp_read_barrier_depends();
		if (ioc)
			break;

		ioc = alloc_io_context(GFP_ATOMIC, -1);
		if (!ioc) {
			err = -ENOMEM;
			break;
		}
		task->io_context = ioc;
	} while (1);

	if (!err) {
		ioc->ioprio = ioprio;
		ioc->ioprio_changed = 1;
	}

	task_unlock(task);
	return err;
}
EXPORT_SYMBOL_GPL(set_task_ioprio);

#ifdef CONFIG_KRG_PROC
static int do_ioprio_set(int which, int who, int ioprio,
			 struct pid_namespace *ns)
#else
SYSCALL_DEFINE3(ioprio_set, int, which, int, who, int, ioprio)
#endif
{
	int class = IOPRIO_PRIO_CLASS(ioprio);
	int data = IOPRIO_PRIO_DATA(ioprio);
	struct task_struct *p, *g;
	struct user_struct *user;
	struct pid *pgrp;
	int ret;

	switch (class) {
		case IOPRIO_CLASS_RT:
			if (!capable(CAP_SYS_ADMIN))
				return -EPERM;
			/* fall through, rt has prio field too */
		case IOPRIO_CLASS_BE:
			if (data >= IOPRIO_BE_NR || data < 0)
				return -EINVAL;

			break;
		case IOPRIO_CLASS_IDLE:
			break;
		case IOPRIO_CLASS_NONE:
			if (data)
				return -EINVAL;
			break;
		default:
			return -EINVAL;
	}

	ret = -ESRCH;
	/*
	 * We want IOPRIO_WHO_PGRP/IOPRIO_WHO_USER to be "atomic",
	 * so we can't use rcu_read_lock(). See re-copy of ->ioprio
	 * in copy_process().
	 */
	read_lock(&tasklist_lock);
	switch (which) {
		case IOPRIO_WHO_PROCESS:
			if (!who)
				p = current;
			else
#ifdef CONFIG_KRG_PROC
				p = find_task_by_pid_ns(who, ns);
#else
				p = find_task_by_vpid(who);
#endif
			if (p)
				ret = set_task_ioprio(p, ioprio);
			break;
		case IOPRIO_WHO_PGRP:
#ifdef CONFIG_KRG_PROC
			BUG_ON(!who);
			pgrp = find_pid_ns(who, ns);
#else
			if (!who)
				pgrp = task_pgrp(current);
			else
				pgrp = find_vpid(who);
#endif
			do_each_pid_thread(pgrp, PIDTYPE_PGID, p) {
				ret = set_task_ioprio(p, ioprio);
				if (ret)
					break;
			} while_each_pid_thread(pgrp, PIDTYPE_PGID, p);
			break;
		case IOPRIO_WHO_USER:
			if (!who)
				user = current_user();
			else
				user = find_user(who);

			if (!user)
				break;

			do_each_thread(g, p) {
				if (__task_cred(p)->uid != who)
					continue;
				ret = set_task_ioprio(p, ioprio);
				if (ret)
					goto free_uid;
			} while_each_thread(g, p);
free_uid:
			if (who)
				free_uid(user);
			break;
		default:
			ret = -EINVAL;
	}

	read_unlock(&tasklist_lock);
	return ret;
}

#ifdef CONFIG_KRG_PROC

struct ioprio_set_msg
{
	int which;
	int who;
	int ioprio;
};

static int handle_ioprio_set_pg_user(struct rpc_desc *desc, void *msg,
				     size_t size)
{
	const struct cred *old_cred;
	struct ioprio_set_msg *_msg = msg;
	struct pid_namespace *ns;
	int retval;

	old_cred = unpack_override_creds(desc);
	if (IS_ERR(old_cred)) {
		retval = PTR_ERR(old_cred);
		goto err_cancel;
	}

	ns = find_get_krg_pid_ns();

	retval = do_ioprio_set(_msg->which, _msg->who, _msg->ioprio, ns);

	put_pid_ns(ns);

	revert_creds(old_cred);

out:
	return retval;

err_cancel:
	rpc_cancel(desc);
	goto out;
}

static int krg_ioprio_set_pg_user(int which, int who, int ioprio)
{
	struct rpc_desc *desc;
	struct ioprio_set_msg msg;
	krgnodemask_t nodes;
	kerrighed_node_t node;
	int retval = -ESRCH, noderet, err;

	BUG_ON(!current->nsproxy->krg_ns
	       || !is_krg_pid_ns_root(task_active_pid_ns(current)));

	if (which == IOPRIO_WHO_PGRP
	    && !(who & GLOBAL_PID_MASK))
		goto out;

	krgnodes_copy(nodes, krgnode_online_map);

	desc = rpc_begin_m(PROC_IOPRIO_SET_PG_USER, &nodes);
	if (!desc) {
		retval = -ENOMEM;
		goto out;
	}

	msg.which = which;
	msg.who = who;
	msg.ioprio = ioprio;

	retval = rpc_pack_type(desc, msg);
	if (retval)
		goto err_cancel;
	retval = pack_creds(desc, current_cred());
	if (retval)
		goto err_cancel;

	retval = -ESRCH;
	for_each_krgnode_mask(node, nodes) {
		err = rpc_unpack_type_from(desc, node, noderet);
		if (err) {
			retval = err;
			goto err_cancel;
		}
		if (noderet != -ESRCH) {
			if (noderet < 0 || (noderet == 0 && retval == -ESRCH))
				retval = noderet;
		}
	}

out_end:
	rpc_end(desc, 0);

out:
	return retval;

err_cancel:
	rpc_cancel(desc);
	goto out_end;
}

static int handle_ioprio_set_process(struct rpc_desc *desc, void *msg,
				     size_t size)
{
	struct pid *pid;
	const struct cred *old_cred;
	int ioprio;
	int retval;

	pid = krg_handle_remote_syscall_begin(desc, msg, size,
					      &ioprio, &old_cred);
	if (IS_ERR(pid)) {
		retval = PTR_ERR(pid);
		goto out;
	}

	retval = do_ioprio_set(IOPRIO_WHO_PROCESS, pid_knr(pid), ioprio,
			       ns_of_pid(pid)->krg_ns_root);

	krg_handle_remote_syscall_end(pid, old_cred);

out:
	return retval;
}

static int krg_ioprio_set_process(pid_t pid, int ioprio)
{
	return krg_remote_syscall_simple(PROC_IOPRIO_SET_PROCESS, pid,
					 &ioprio, sizeof(ioprio));
}

SYSCALL_DEFINE3(ioprio_set, int, which, int, _who, int, ioprio)
{
	int ret;
	int who = _who;

	if (which == IOPRIO_WHO_PGRP && !who)
		who = pid_nr_ns(task_pgrp(current),
				task_active_pid_ns(current));

	if (!current->nsproxy->krg_ns
	    || !is_krg_pid_ns_root(task_active_pid_ns(current))) {
		/* not in the kerrighed container */
		ret = do_ioprio_set(which, who, ioprio,
				    task_active_pid_ns(current));
		goto out;
	}

	switch (which) {
	case IOPRIO_WHO_PROCESS:
		/* make a first try locally */
		ret = do_ioprio_set(which, who, ioprio,
				    task_active_pid_ns(current));
		if (ret == -ESRCH)
			ret = krg_ioprio_set_process(who, ioprio);
		break;
	case IOPRIO_WHO_PGRP:
	case IOPRIO_WHO_USER:
		ret = krg_ioprio_set_pg_user(which, who, ioprio);
		break;
	default:
		ret = -EINVAL;
		break;
	}

out:
	return ret;
}
#endif

static int get_task_ioprio(struct task_struct *p)
{
	int ret;

	ret = security_task_getioprio(p);
	if (ret)
		goto out;
	ret = IOPRIO_PRIO_VALUE(IOPRIO_CLASS_NONE, IOPRIO_NORM);
	if (p->io_context)
		ret = p->io_context->ioprio;
out:
	return ret;
}

int ioprio_best(unsigned short aprio, unsigned short bprio)
{
	unsigned short aclass = IOPRIO_PRIO_CLASS(aprio);
	unsigned short bclass = IOPRIO_PRIO_CLASS(bprio);

	if (aclass == IOPRIO_CLASS_NONE)
		aclass = IOPRIO_CLASS_BE;
	if (bclass == IOPRIO_CLASS_NONE)
		bclass = IOPRIO_CLASS_BE;

	if (aclass == bclass)
		return min(aprio, bprio);
	if (aclass > bclass)
		return bprio;
	else
		return aprio;
}

#ifdef CONFIG_KRG_PROC
static int do_ioprio_get(int which, int who, struct pid_namespace *ns)
#else
SYSCALL_DEFINE2(ioprio_get, int, which, int, who)
#endif
{
	struct task_struct *g, *p;
	struct user_struct *user;
	struct pid *pgrp;
	int ret = -ESRCH;
	int tmpio;

	read_lock(&tasklist_lock);
	switch (which) {
		case IOPRIO_WHO_PROCESS:
			if (!who)
				p = current;
			else
#ifdef CONFIG_KRG_PROC
				p = find_task_by_vpid(who);
#else
				p = find_task_by_pid_ns(who, ns);
#endif
			if (p)
				ret = get_task_ioprio(p);
			break;
		case IOPRIO_WHO_PGRP:
#ifdef CONFIG_KRG_PROC
			BUG_ON(!who);
			pgrp = find_pid_ns(who, ns);
#else
			if (!who)
				pgrp = task_pgrp(current);
			else
				pgrp = find_vpid(who);
#endif
			do_each_pid_thread(pgrp, PIDTYPE_PGID, p) {
				tmpio = get_task_ioprio(p);
				if (tmpio < 0)
					continue;
				if (ret == -ESRCH)
					ret = tmpio;
				else
					ret = ioprio_best(ret, tmpio);
			} while_each_pid_thread(pgrp, PIDTYPE_PGID, p);
			break;
		case IOPRIO_WHO_USER:
			if (!who)
				user = current_user();
			else
				user = find_user(who);

			if (!user)
				break;

			do_each_thread(g, p) {
				if (__task_cred(p)->uid != user->uid)
					continue;
				tmpio = get_task_ioprio(p);
				if (tmpio < 0)
					continue;
				if (ret == -ESRCH)
					ret = tmpio;
				else
					ret = ioprio_best(ret, tmpio);
			} while_each_thread(g, p);

			if (who)
				free_uid(user);
			break;
		default:
			ret = -EINVAL;
	}

	read_unlock(&tasklist_lock);
	return ret;
}

#ifdef CONFIG_KRG_PROC
struct ioprio_get_msg
{
	int which;
	int who;
};

static int handle_ioprio_get_pg_user(struct rpc_desc *desc, void *msg,
				     size_t size)
{
	const struct cred *old_cred;
	struct ioprio_get_msg *_msg = msg;
	struct pid_namespace *ns;
	int retval;

	old_cred = unpack_override_creds(desc);
	if (IS_ERR(old_cred)) {
		retval = PTR_ERR(old_cred);
		goto err_cancel;
	}

	ns = find_get_krg_pid_ns();

	retval = do_ioprio_get(_msg->which, _msg->who, ns);

	put_pid_ns(ns);

	revert_creds(old_cred);

out:
	return retval;

err_cancel:
	rpc_cancel(desc);
	goto out;
}

static int krg_ioprio_get_pg_user(int which, int who)
{
	struct rpc_desc *desc;
	struct ioprio_get_msg msg;
	krgnodemask_t nodes;
	kerrighed_node_t node;
	int retval = -ESRCH, noderet, err;

	BUG_ON(!current->nsproxy->krg_ns
	       || !is_krg_pid_ns_root(task_active_pid_ns(current)));

	if (which == IOPRIO_WHO_PGRP
	    && !(who & GLOBAL_PID_MASK))
		goto out;

	krgnodes_copy(nodes, krgnode_online_map);

	desc = rpc_begin_m(PROC_IOPRIO_GET_PG_USER, &nodes);
	if (!desc) {
		retval = -ENOMEM;
		goto out;
	}

	msg.which = which;
	msg.who = who;

	retval = rpc_pack_type(desc, msg);
	if (retval)
		goto err_cancel;
	retval = pack_creds(desc, current_cred());
	if (retval)
		goto err_cancel;

	retval = -ESRCH;
	for_each_krgnode_mask(node, nodes) {
		err = rpc_unpack_type_from(desc, node, noderet);
		if (err) {
			retval = err;
			goto err_cancel;
		}

		if (noderet < 0) {
			if (noderet != -ESRCH)
				retval = noderet;
		} else if ((retval >= 0 && noderet > retval) || retval == -ESRCH)
			retval = noderet;
	}

out_end:
	rpc_end(desc, 0);

out:
	return retval;

err_cancel:
	rpc_cancel(desc);
	goto out_end;
}

static int handle_ioprio_get_process(struct rpc_desc *desc, void *msg,
				     size_t size)
{
	struct pid *pid;
	const struct cred *old_cred;
	int retval;

	pid = krg_handle_remote_syscall_begin(desc, msg, size,
					      NULL, &old_cred);
	if (IS_ERR(pid)) {
		retval = PTR_ERR(pid);
		goto out;
	}

	retval = do_ioprio_get(IOPRIO_WHO_PROCESS, pid_knr(pid),
			       ns_of_pid(pid)->krg_ns_root);

	krg_handle_remote_syscall_end(pid, old_cred);

out:
	return retval;
}

static int krg_ioprio_get_process(pid_t pid)
{
	return krg_remote_syscall_simple(PROC_IOPRIO_GET_PROCESS, pid,
					 NULL, 0);
}

SYSCALL_DEFINE2(ioprio_get, int, which, int, _who)
{
	int retval;
	int who = _who;

	if (which == IOPRIO_WHO_PGRP && !who)
		who = pid_nr_ns(task_pgrp(current),
				task_active_pid_ns(current));

	if (!current->nsproxy->krg_ns
	    || !is_krg_pid_ns_root(task_active_pid_ns(current))) {
		/* not in the kerrighed container */
		retval = do_ioprio_get(which, who,
				       task_active_pid_ns(current));
		goto out;
	}

	switch (which) {

	case IOPRIO_WHO_PROCESS:
		/* make a first try locally */
		retval = do_ioprio_get(which, who,
				       task_active_pid_ns(current));

		if (retval == -ESRCH)
			retval = krg_ioprio_get_process(who);
		break;
	case IOPRIO_WHO_PGRP:
	case IOPRIO_WHO_USER:
		retval = krg_ioprio_get_pg_user(which, who);
		break;
	default:
		retval = -EINVAL;
		break;
	}

out:
	return retval;
}

void remote_ioprio_init(void)
{
	rpc_register_int(PROC_IOPRIO_GET_PROCESS, handle_ioprio_get_process, 0);
	rpc_register_int(PROC_IOPRIO_GET_PG_USER, handle_ioprio_get_pg_user, 0);
	rpc_register_int(PROC_IOPRIO_SET_PROCESS, handle_ioprio_set_process, 0);
	rpc_register_int(PROC_IOPRIO_SET_PG_USER, handle_ioprio_set_pg_user, 0);
}
#endif
