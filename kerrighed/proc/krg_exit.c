/*
 *  kerrighed/proc/krg_exit.c
 *
 *  Copyright (C) 2006-2007 Pascal Gallard - Kerlabs, Louis Rilling - Kerlabs
 */

#include <linux/types.h>
#include <linux/module.h>
#include <linux/personality.h>
#include <linux/sched.h>
#include <linux/workqueue.h>
#include <linux/rcupdate.h>
#include <kerrighed/task.h>
#ifdef CONFIG_KRG_EPM
#include <linux/uaccess.h>
#include <kerrighed/sys/types.h>
#include <kerrighed/krginit.h>
#include <kerrighed/children.h>
#include <kerrighed/signal.h>
#include <kerrighed/sched.h>
#include <kerrighed/krgnodemask.h>
#include <asm/cputime.h>
#endif

#ifdef CONFIG_KRG_EPM
#include <tools/workqueue.h>
#endif
#include <kerrighed/hotplug.h>
#include <net/krgrpc/rpcid.h>
#include <net/krgrpc/rpc.h>
#include <kerrighed/task.h>
#include <kerrighed/krg_exit.h>
#ifdef CONFIG_KRG_EPM
#include <epm/action.h>
#include <epm/migration.h>
#endif

#ifdef CONFIG_KRG_EPM

static void delay_release_task_worker(struct work_struct *work);
static DECLARE_WORK(delay_release_task_work, delay_release_task_worker);
static LIST_HEAD(tasks_to_release);
static DEFINE_SPINLOCK(tasks_to_release_lock);

struct notify_parent_request {
	pid_t parent_pid;
	unsigned long ptrace;
	struct siginfo info;
};

struct notify_parent_result {
	int exit_signal;
};

static void handle_do_notify_parent(struct rpc_desc *desc,
				    void *msg, size_t size)
{
	struct notify_parent_request *req = msg;
	struct notify_parent_result res;
	struct task_struct *parent;
	struct sighand_struct *psig;
	int sig = req->info.si_signo;
	int err;

	res.exit_signal = 0;

	read_lock(&tasklist_lock);
	parent = find_task_by_pid(req->parent_pid);
	BUG_ON(!parent);

	/* Adapted from do_notify_parent for a remote child */

	psig = parent->sighand;
	spin_lock_irq(&psig->siglock);
	if (!req->ptrace && sig == SIGCHLD &&
	    (psig->action[SIGCHLD-1].sa.sa_handler == SIG_IGN ||
	     (psig->action[SIGCHLD-1].sa.sa_flags & SA_NOCLDWAIT))) {
		/*
		 * We are exiting and our parent doesn't care.  POSIX.1
		 * defines special semantics for setting SIGCHLD to SIG_IGN
		 * or setting the SA_NOCLDWAIT flag: we should be reaped
		 * automatically and not left for our parent's wait4 call.
		 * Rather than having the parent do it as a magic kind of
		 * signal handler, we just set this to tell do_exit that we
		 * can be cleaned up without becoming a zombie.  Note that
		 * we still call __wake_up_parent in this case, because a
		 * blocked sys_wait4 might now return -ECHILD.
		 *
		 * Whether we send SIGCHLD or not for SA_NOCLDWAIT
		 * is implementation-defined: we do (if you don't want
		 * it, just use SIG_IGN instead).
		 */
		res.exit_signal = -1;
		if (psig->action[SIGCHLD-1].sa.sa_handler == SIG_IGN)
			sig = 0;
	}
	if (valid_signal(sig) && sig > 0)
		__group_send_sig_info(sig, &req->info, parent);
	wake_up_interruptible_sync(&parent->signal->wait_chldexit);
	spin_unlock_irq(&psig->siglock);

	read_unlock(&tasklist_lock);

	err = rpc_pack_type(desc, res);
	if (unlikely(err))
		rpc_cancel(desc);
}

/*
 * Expects task->task_obj locked and up to date regarding parent and
 * parent_node
 */
static int kcb_do_notify_parent(struct task_struct *task, struct siginfo *info)
{
	struct notify_parent_request req;
	struct notify_parent_result res;
	kerrighed_node_t parent_node = task->task_obj->parent_node;
	struct rpc_desc *desc;
	int err = -ENOMEM;

	BUG_ON(task->parent != baby_sitter);
	BUG_ON(parent_node == KERRIGHED_NODE_ID_NONE);
	BUG_ON(parent_node == kerrighed_node_id);

	req.parent_pid = task->task_obj->parent;
	req.ptrace = task->ptrace;
	req.info = *info;

	desc = rpc_begin(PROC_DO_NOTIFY_PARENT, parent_node);
	if (unlikely(!desc))
		goto err;
	err = rpc_pack_type(desc, req);
	if (unlikely(err))
		goto err_cancel;
	err = rpc_unpack_type(desc, res);
	if (unlikely(err))
		goto err_cancel;
	rpc_end(desc, 0);

out:
	if (likely(!err) && res.exit_signal == -1)
		return -1;
	return 0;

err_cancel:
	rpc_cancel(desc);
	rpc_end(desc, 0);
err:
	printk(KERN_ERR "error: child %d cannot notify remote parent %d\n",
	       task->pid, req.parent_pid);
	goto out;
}

struct wait_task_request {
	pid_t pid;
	pid_t real_parent_tgid;
	int noreap;
};

struct wait_task_result {
	struct siginfo info;
	int status;
	struct rusage ru;
	cputime_t cutime, cstime;
	unsigned long cmin_flt, cmaj_flt;
	unsigned long cnvcsw, cnivcsw;
};

static void handle_wait_task_zombie(struct rpc_desc *desc,
				    void *_msg, size_t size)
{
	struct wait_task_request *req = _msg;
	struct task_struct *p;
	struct wait_task_result res;
	int retval;
	int err = -ENOMEM;

	read_lock(&tasklist_lock);
	p = find_task_by_pid(req->pid);
	BUG_ON(!p);
	get_task_struct(p);

	retval = wait_task_zombie(p, req->noreap,
				  &res.info,
				  &res.status, &res.ru);
	if (!retval)
		read_unlock(&tasklist_lock);

	err = rpc_pack_type(desc, retval);
	if (err)
		goto err_no_release;
	if (retval) {
		struct signal_struct *sig;

		BUG_ON(retval < 0);
		read_lock(&tasklist_lock);
		sig = p->signal;
		if (sig) {
			res.cutime = cputime_add(p->utime,
						 cputime_add(sig->utime,
							     sig->cutime));
			res.cstime = cputime_add(p->stime,
						 cputime_add(sig->stime,
							     sig->cstime));
			res.cmin_flt =
				p->min_flt + sig->min_flt + sig->cmin_flt;
			res.cmaj_flt =
				p->maj_flt + sig->maj_flt + sig->cmaj_flt;
			res.cnvcsw = p->nvcsw + sig->nvcsw + sig->cnvcsw;
			res.cnivcsw = p->nivcsw + sig->nivcsw + sig->cnivcsw;
		} else {
			res.cutime = cputime_zero;
			res.cstime = cputime_zero;
			res.cmin_flt = 0;
			res.cmaj_flt = 0;
			res.cnvcsw = 0;
			res.cnivcsw = 0;
		}
		read_unlock(&tasklist_lock);
		err = rpc_pack_type(desc, res);
		if (err)
			goto err_no_release;

		if (likely(!req->noreap)) {
			/*
			 * We do not want to release p until we are sure that
			 * requester completes successfully do_wait. Moreover,
			 * requester should not try to reap another child before
			 * p is removed from its children list.
			 */
			err = rpc_unpack_type(desc, retval);
			if (err) {
				/*
				 * Just in case rpc_unpack overwrote part of
				 * retval
				 */
				retval = req->pid;
				goto err_no_release;
			}
			if (!retval) {
				release_task(p);
				/*
				 * Only a synchronization. Requester does not
				 * care about the value of retval.
				 */
				err = rpc_pack_type(desc, retval);
			} else {
				/*
				 * Comment in vanilla do_wait is the
				 * following:
				 */
				// TODO: is this safe?
				p->exit_state = EXIT_ZOMBIE;
			}
		}
	}
	put_task_struct(p);

	return;

err_no_release:
	if (retval > 0 && likely(!req->noreap))
		/*
		 * This is safe as long as no remote ptrace nor ptrace of remote
		 * child is allowed.
		 */
		/* Comment in vanilla do_wait is the following: */
		// TODO: is this safe?
		p->exit_state = EXIT_ZOMBIE;
	put_task_struct(p);
	rpc_cancel(desc);
}

/*
 * Error reporting is a bit weird here. We should return a negative error code
 * only if one of the put_user calls failed. Any other error should return 0.
 */
int krg_wait_task_zombie(pid_t pid, kerrighed_node_t zombie_location,
			 int noreap,
			 struct siginfo __user *infop,
			 int __user *stat_addr, struct rusage __user *ru)
{
	struct wait_task_request req;
	int retval;
	struct wait_task_result res;
	struct rpc_desc *desc;
	int err;

	/*
	 * Zombie's location does not need to remain locked since it won't
	 * change afterwards, but this will be needed to support hot removal of
	 * nodes with zombie migration.
	 */
	BUG_ON(!krgnode_online(zombie_location));

	desc = rpc_begin(PROC_WAIT_TASK_ZOMBIE, zombie_location);
	if (!desc)
		return 0;

	req.pid = pid;
	/* True as long as no remote ptrace is allowed */
	req.real_parent_tgid = current->tgid;
	req.noreap = noreap;
	err = rpc_pack_type(desc, req);
	if (err)
		goto err_cancel;

	err = rpc_unpack_type(desc, retval);
	if (err)
		goto err_cancel;
	if (retval) {
		BUG_ON(retval < 0);
		err = rpc_unpack_type(desc, res);
		if (err)
			goto err_cancel;

		retval = 0;
		if (ru)
			retval = copy_to_user(ru, &res.ru, sizeof(res.ru)) ?
				-EFAULT : 0;
		if (!retval && stat_addr && likely(!noreap))
			retval = put_user(res.status, stat_addr);
		if (!retval && infop) {
			retval = put_user(res.info.si_signo, &infop->si_signo);
			if (!retval)
				retval = put_user(res.info.si_errno,
						  &infop->si_errno);
			if (!retval)
				retval = put_user(res.info.si_code,
						  &infop->si_code);
			if (!retval)
				retval = put_user(res.info.si_status,
						  &infop->si_status);
			if (!retval)
				retval = put_user(res.info.si_pid,
						  &infop->si_pid);
			if (!retval)
				retval = put_user(res.info.si_uid,
						  &infop->si_uid);
		}

		if (likely(!noreap)) {
			if (!retval) {
				struct signal_struct *psig;

				spin_lock_irq(&current->sighand->siglock);
				psig = current->signal;
				psig->cutime = cputime_add(psig->cutime,
							   res.cutime);
				psig->cstime = cputime_add(psig->cstime,
							   res.cstime);
				psig->cmin_flt += res.cmin_flt;
				psig->cmaj_flt += res.cmaj_flt;
				psig->cnvcsw += res.cnvcsw;
				psig->cnivcsw += res.cnivcsw;
				spin_unlock_irq(&current->sighand->siglock);
			}

			/* Tell remote node whether task can be released */
			err = rpc_pack_type(desc, retval);
			if (err)
				goto err_cancel;
			if (!retval) {
				/*
				 * Only a synchronization. We do not care about
				 * the value of retval.
				 */
				err = rpc_unpack_type(desc, retval);
				if (!err)
					retval = req.pid;
			}
		}
	}
out:
	if (err)
		rpc_cancel(desc);
	rpc_end(desc, 0);

	return retval;

err_cancel:
	retval = 0;
	goto out;
}

#endif /* CONFIG_KRG_EPM */

static void *kh_release_task;

void krg_release_task(struct task_struct *p)
{
	if (!kh_release_task)
		return;

#ifdef CONFIG_KRG_EPM
	kh_exit_application(p);
#ifdef CONFIG_KRG_SCHED
	kh_free_sched_info(p);
#endif
	kcb_unhash_process(p);
	if (p->exit_state != EXIT_MIGRATION) {
#endif
		krg_task_free(p);
#ifdef CONFIG_KRG_EPM
		if (krg_action_pending(p, EPM_MIGRATE))
			/* Migration aborted because p died before */
			migration_aborted(p);
	}
#endif
}

#ifdef CONFIG_KRG_EPM

/*
 * To chain the tasks to release in the worker, we overload the children field
 * of the task_struct, which is no more used once a task is ready to release.
 */
static void delay_release_task_worker(struct work_struct *work)
{
	struct task_struct *task;

	for (;;) {
		task = NULL;
		spin_lock(&tasks_to_release_lock);
		if (!list_empty(&tasks_to_release)) {
			task = list_entry(tasks_to_release.next,
					  struct task_struct, children);
			list_del_init(&task->children);
		}
		spin_unlock(&tasks_to_release_lock);
		if (!task)
			break;
		release_task(task);
	}
}

static void kcb_delay_release_task(struct task_struct *task)
{
	BUG_ON(!list_empty(&task->children));

	spin_lock(&tasks_to_release_lock);
	list_add_tail(&task->children, &tasks_to_release);
	spin_unlock(&tasks_to_release_lock);

	queue_work(krg_wq, &delay_release_task_work);
}

struct notify_remote_child_reaper_msg {
	pid_t zombie_pid;
};

static void handle_notify_remote_child_reaper(struct rpc_desc *desc,
					      void *_msg,
					      size_t size)
{
	struct notify_remote_child_reaper_msg *msg = _msg;
	struct task_struct *zombie;

	krg_task_writelock(msg->zombie_pid);
	write_lock_irq(&tasklist_lock);

	zombie = find_task_by_pid(msg->zombie_pid);
	BUG_ON(!zombie);

	/* Real parent died and let us reparent zombie to local init. */
	kh_reparent_to_local_child_reaper(zombie);

	BUG_ON(zombie->exit_state != EXIT_ZOMBIE);
	BUG_ON(zombie->exit_signal == -1);
	if (!zombie->ptrace && thread_group_empty(zombie))
		do_notify_parent(zombie, zombie->exit_signal);

	write_unlock_irq(&tasklist_lock);
	krg_task_unlock(msg->zombie_pid);
}

void notify_remote_child_reaper(pid_t zombie_pid,
				kerrighed_node_t zombie_location)
{
	struct notify_remote_child_reaper_msg msg = {
		.zombie_pid = zombie_pid
	};

	BUG_ON(zombie_location == KERRIGHED_NODE_ID_NONE);
	BUG_ON(zombie_location == kerrighed_node_id);

	rpc_async(PROC_NOTIFY_REMOTE_CHILD_REAPER, zombie_location,
		  &msg, sizeof(msg));
}

#endif /* CONFIG_KRG_EPM */

void register_krg_exit_hooks(void)
{
#ifdef CONFIG_KRG_EPM
	hook_register(&kh_do_notify_parent, kcb_do_notify_parent);
	hook_register(&kh_delay_release_task, kcb_delay_release_task);
#endif
	hook_register(&kh_release_task, (void *)true);
}

/**
 * @author Pascal Gallard, Louis Rilling
 */
void proc_krg_exit_start(void)
{
#ifdef CONFIG_KRG_EPM
	rpc_register_void(PROC_DO_NOTIFY_PARENT, handle_do_notify_parent, 0);
	rpc_register_void(PROC_NOTIFY_REMOTE_CHILD_REAPER,
			  handle_notify_remote_child_reaper, 0);
	rpc_register_void(PROC_WAIT_TASK_ZOMBIE, handle_wait_task_zombie, 0);
#endif
}

/**
 * @author Pascal Gallard, Louis Rilling
 */
void proc_krg_exit_exit(void)
{
}
