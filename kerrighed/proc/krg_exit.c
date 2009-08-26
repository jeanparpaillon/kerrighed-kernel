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
#include <linux/tracehook.h>
#include <linux/task_io_accounting_ops.h>
#include <kerrighed/sys/types.h>
#include <kerrighed/krginit.h>
#include <kerrighed/pid.h>
#include <kerrighed/children.h>
#include <kerrighed/signal.h>
#include <kerrighed/application.h>
#include <kerrighed/krgnodemask.h>
#include <asm/cputime.h>
#endif
#ifdef CONFIG_KRG_SCHED
#include <kerrighed/scheduler/info.h>
#endif

#ifdef CONFIG_KRG_EPM
#include <kerrighed/workqueue.h>
#endif
#include <net/krgrpc/rpcid.h>
#include <net/krgrpc/rpc.h>
#include <kerrighed/task.h>
#include <kerrighed/krg_exit.h>
#ifdef CONFIG_KRG_EPM
#include <kerrighed/action.h>
#include <kerrighed/migration.h>
#endif

#ifdef CONFIG_KRG_EPM

static void delay_release_task_worker(struct work_struct *work);
static DECLARE_WORK(delay_release_task_work, delay_release_task_worker);
static LIST_HEAD(tasks_to_release);
static DEFINE_SPINLOCK(tasks_to_release_lock);

struct notify_parent_request {
	pid_t parent_pid;
	unsigned int ptrace;
	struct siginfo info;
};

static void handle_do_notify_parent(struct rpc_desc *desc,
				    void *msg, size_t size)
{
	struct notify_parent_request *req = msg;
	struct task_struct *parent;
	struct sighand_struct *psig;
	int sig = req->info.si_signo;
	int err, ret;

	ret = sig;

	read_lock(&tasklist_lock);
	parent = find_task_by_pid_ns(req->parent_pid, &init_pid_ns);
	BUG_ON(!parent);

	/* Adapted from do_notify_parent() for a remote child */

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
		ret = -1;
		if (psig->action[SIGCHLD-1].sa.sa_handler == SIG_IGN)
			sig = -1;
	}
	if (valid_signal(sig) && sig > 0)
		__group_send_sig_info(sig, &req->info, parent);
	wake_up_interruptible_sync(&parent->signal->wait_chldexit);
	spin_unlock_irq(&psig->siglock);

	read_unlock(&tasklist_lock);

	err = rpc_pack_type(desc, ret);
	if (err)
		rpc_cancel(desc);
}

/*
 * Expects task->task_obj locked and up to date regarding parent and
 * parent_node
 */
int krg_do_notify_parent(struct task_struct *task, struct siginfo *info)
{
	struct notify_parent_request req;
	int ret;
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
	if (!desc)
		goto err;
	err = rpc_pack_type(desc, req);
	if (err)
		goto err_cancel;
	err = rpc_unpack_type(desc, ret);
	if (err)
		goto err_cancel;
	rpc_end(desc, 0);

out:
	if (!err)
		return ret;
	return 0;

err_cancel:
	rpc_cancel(desc);
	rpc_end(desc, 0);
err:
	printk(KERN_ERR "error: child %d cannot notify remote parent %d\n",
	       task->pid, req.parent_pid);
	goto out;
}

/*
 * If return value is not NULL, all variables are set, and the children kddm
 * object will have to be unlocked with krg_children_unlock(@return),
 * and parent pid location will have to be unlocked with
 * krg_unlock_pid_location(*parent_pid_p)
 *
 * If return value is NULL, parent has no children kddm object. It is up to the
 * caller to know whether original parent died or is still alive and never had a
 * children kddm object.
 */
static
struct children_kddm_object *
parent_children_writelock_pid_location_lock(struct task_struct *task,
					    pid_t *real_parent_tgid_p,
					    pid_t *real_parent_pid_p,
					    pid_t *parent_pid_p,
					    kerrighed_node_t *parent_node_p)
{
	struct children_kddm_object *children_obj;
	pid_t real_parent_tgid;
	pid_t real_parent_pid;
	pid_t parent_pid;
	struct task_kddm_object *obj;
	kerrighed_node_t parent_node = KERRIGHED_NODE_ID_NONE;
	struct timespec backoff_time = {
		.tv_sec = 1,
		.tv_nsec = 0
	};	/* 1 second */

	/*
	 * Similar to krg_lock_pid_location but we need to acquire
	 * parent_children_writelock at the same time without deadlocking with
	 * migration
	 */
	for (;;) {
		children_obj = krg_parent_children_writelock(task,
							     &real_parent_tgid);
		if (!children_obj)
			break;
		krg_get_parent(children_obj, task->pid,
			       &parent_pid, &real_parent_pid);
		obj = krg_task_readlock(parent_pid);
		BUG_ON(!obj);
		parent_node = obj->node;
		if (parent_node != KERRIGHED_NODE_ID_NONE)
			break;
		krg_task_unlock(parent_pid);
		krg_children_unlock(children_obj);

		set_current_state(TASK_UNINTERRUPTIBLE);
		schedule_timeout(timespec_to_jiffies(&backoff_time) + 1);
	}
	BUG_ON(children_obj && parent_node == KERRIGHED_NODE_ID_NONE);

	/*
	 * If children_obj is not NULL, then children_obj is write-locked and
	 * obj is read-locked,
	 * otherwise none is locked.
	 */
	if (children_obj) {
		*real_parent_tgid_p = real_parent_tgid;
		*real_parent_pid_p = real_parent_pid;
		*parent_pid_p = parent_pid;
		*parent_node_p = parent_node;
	}
	return children_obj;
}

int krg_delayed_notify_parent(struct task_struct *leader)
{
	struct children_kddm_object *parent_children_obj;
	pid_t real_parent_tgid;
	pid_t parent_pid, real_parent_pid;
	kerrighed_node_t parent_node;
	int zap_leader;

	parent_children_obj = parent_children_writelock_pid_location_lock(
				leader,
				&real_parent_tgid,
				&real_parent_pid,
				&parent_pid,
				&parent_node);
	__krg_task_writelock_nested(leader);

	write_lock_irq(&tasklist_lock);
	BUG_ON(task_detached(leader));
	/*
	 * Needed to check whether we were reparented to init, and to
	 * know which task to notify in case parent is still remote
	 */
	if (parent_children_obj) {
		/* Make sure that task_obj is up to date */
		krg_update_parents(leader, parent_pid, real_parent_pid);
		leader->task_obj->parent_node = parent_node;
	} else if (leader->real_parent == baby_sitter
		   || leader->parent == baby_sitter) {
		/* Real parent died and let us reparent leader to local init. */
		krg_reparent_to_local_child_reaper(leader);
	}

	do_notify_parent(leader, leader->exit_signal);

	zap_leader = task_detached(leader);
	if (zap_leader)
		leader->exit_state = EXIT_DEAD;
	write_unlock_irq(&tasklist_lock);

	__krg_task_unlock(leader);
	if (parent_children_obj) {
		krg_unlock_pid_location(parent_pid);
		if (zap_leader)
			/*
			 * Parent was not interested by notification,
			 * but may have been woken up in do_wait and
			 * should not see leader as a child
			 * anymore. Remove leader from its children kddm
			 * object before parent can access it again.
			 */
			krg_remove_child(parent_children_obj, leader);
		krg_children_unlock(parent_children_obj);
	}

	return zap_leader;
}

struct wait_task_request {
	pid_t pid;
	pid_t real_parent_tgid;
	int options;
};

struct wait_task_result {
	struct siginfo info;
	int status;
	struct rusage ru;
	cputime_t cutime, cstime, cgtime;
	unsigned long cmin_flt, cmaj_flt;
	unsigned long cnvcsw, cnivcsw;
	unsigned long cinblock, coublock;
	struct task_io_accounting ioac;
};

static void handle_wait_task_zombie(struct rpc_desc *desc,
				    void *_msg, size_t size)
{
	struct wait_task_request *req = _msg;
	struct task_struct *p;
	struct signal_struct *sig;
	struct task_cputime cputime;
	struct wait_task_result res;
	int retval;
	int err = -ENOMEM;

	read_lock(&tasklist_lock);
	p = find_task_by_pid_ns(req->pid, &init_pid_ns);
	BUG_ON(!p);

	/*
	 * Sample resource counters now since wait_task_zombie() may release p.
	 */
	if (!(req->options & WNOWAIT)) {
		sig = p->signal;

		thread_group_cputime(p, &cputime);
		res.cutime = cputime_add(cputime.utime, sig->cutime);
		res.cstime = cputime_add(cputime.stime, sig->cstime);
		res.cgtime = cputime_add(p->gtime,
					 cputime_add(sig->gtime, sig->cgtime));
		res.cmin_flt = p->min_flt + sig->min_flt + sig->cmin_flt;
		res.cmaj_flt = p->maj_flt + sig->maj_flt + sig->cmaj_flt;
		res.cnvcsw = p->nvcsw + sig->nvcsw + sig->cnvcsw;
		res.cnivcsw = p->nivcsw + sig->nivcsw + sig->cnivcsw;
		res.cinblock = task_io_get_inblock(p) +
				sig->inblock + sig->cinblock;
		res.coublock = task_io_get_oublock(p) +
				sig->oublock + sig->coublock;
		res.ioac = p->ioac;
		task_io_accounting_add(&res.ioac, &sig->ioac);
	}
	retval = wait_task_zombie(p, req->options,
				  &res.info,
				  &res.status, &res.ru);
	if (!retval)
		read_unlock(&tasklist_lock);

	err = rpc_pack_type(desc, retval);
	if (err)
		goto err_cancel;
	if (retval) {
		BUG_ON(retval < 0);
		err = rpc_pack_type(desc, res);
		if (err)
			goto err_cancel;
	}

	return;

err_cancel:
	rpc_cancel(desc);
}

int krg_wait_task_zombie(pid_t pid, kerrighed_node_t zombie_location,
			 int options,
			 struct siginfo __user *infop,
			 int __user *stat_addr, struct rusage __user *ru)
{
	struct wait_task_request req;
	int retval;
	struct wait_task_result res;
	struct rpc_desc *desc;
	bool noreap = options & WNOWAIT;
	int err;

	/*
	 * Zombie's location does not need to remain locked since it won't
	 * change afterwards, but this will be needed to support hot removal of
	 * nodes with zombie migration.
	 */
	BUG_ON(!krgnode_possible(zombie_location));

	desc = rpc_begin(PROC_WAIT_TASK_ZOMBIE, zombie_location);
	if (!desc)
		return -ENOMEM;

	req.pid = pid;
	/* True as long as no remote ptrace is allowed */
	req.real_parent_tgid = current->tgid;
	req.options = options;
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

		if (likely(!noreap)) {
			struct signal_struct *psig;

			spin_lock_irq(&current->sighand->siglock);
			psig = current->signal;
			psig->cutime = cputime_add(psig->cutime,
						   res.cutime);
			psig->cstime = cputime_add(psig->cstime,
						   res.cstime);
			psig->cgtime = cputime_add(psig->cgtime,
						   res.cgtime);
			psig->cmin_flt += res.cmin_flt;
			psig->cmaj_flt += res.cmaj_flt;
			psig->cnvcsw += res.cnvcsw;
			psig->cnivcsw += res.cnivcsw;
			psig->cinblock += res.cinblock;
			psig->coublock += res.coublock;
			task_io_accounting_add(&psig->ioac, &res.ioac);
			spin_unlock_irq(&current->sighand->siglock);
		}

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
		if (!retval)
			retval = pid;
	}
out:
	rpc_end(desc, 0);

	return retval;

err_cancel:
	rpc_cancel(desc);
	if (err > 0)
		err = -EPIPE;
	retval = err;
	goto out;
}

struct children_kddm_object *
krg_prepare_exit_ptrace_task(struct task_struct *tracer,
			     struct task_struct *task)
{
	struct children_kddm_object *obj;
	pid_t real_parent_tgid, real_parent_pid, parent_pid;
	kerrighed_node_t parent_node;

	/* Prepare a call to do_notify_parent() in __ptrace_detach() */

	/*
	 * Note: real parent should be locked, not parent. However the children
	 * object only records real parent, so it's ok.
	 */
	obj = rcu_dereference(task->parent_children_obj);
	if (obj)
		obj = parent_children_writelock_pid_location_lock(
			task,
			&real_parent_tgid,
			&real_parent_pid,
			&parent_pid,
			&parent_node);
	if (obj)
		__krg_task_writelock_nested(task);
	else
		__krg_task_writelock(task);

	krg_set_child_ptraced(obj, task, 0);

	write_lock_irq(&tasklist_lock);
	BUG_ON(!task->ptrace);

	if (obj && task->task_obj) {
		krg_update_parents(task, parent_pid, real_parent_pid);
		task->task_obj->parent_node = parent_node;
	} else if (!obj && task->real_parent == baby_sitter) {
		krg_reparent_to_local_child_reaper(task);
	}

	return obj;
}

void krg_finish_exit_ptrace_task(struct task_struct *task,
				 struct children_kddm_object *obj,
				 bool dead)
{
	pid_t parent_pid;

	if (task->real_parent == baby_sitter)
		parent_pid = task->task_obj->parent;
	else
		parent_pid = task->real_parent->pid;

	write_unlock_irq(&tasklist_lock);

	if (obj) {
		krg_unlock_pid_location(parent_pid);
		if (dead)
			krg_remove_child(obj, task);
		krg_children_unlock(obj);
	}
	__krg_task_unlock(task);
}

#endif /* CONFIG_KRG_EPM */

void *krg_prepare_exit_notify(struct task_struct *task)
{
	void *cookie = NULL;
#ifdef CONFIG_KRG_EPM
	pid_t real_parent_tgid = 0;
	pid_t real_parent_pid = 0;
	pid_t parent_pid = 0;
	kerrighed_node_t parent_node = KERRIGHED_NODE_ID_NONE;
#endif

#ifdef CONFIG_KRG_EPM
	if (rcu_dereference(task->parent_children_obj))
		cookie = parent_children_writelock_pid_location_lock(
				task,
				&real_parent_tgid,
				&real_parent_pid,
				&parent_pid,
				&parent_node);
#endif /* CONFIG_KRG_EPM */

	if (task->task_obj) {
		if (cookie)
			__krg_task_writelock_nested(task);
		else
			__krg_task_writelock(task);

#ifdef CONFIG_KRG_EPM
		write_lock_irq(&tasklist_lock);
		if (cookie) {
			/* Make sure that task_obj is up to date */
			krg_update_parents(task, parent_pid, real_parent_pid);
			task->task_obj->parent_node = parent_node;
		} else if (task->real_parent == baby_sitter
			   || task->parent == baby_sitter) {
			/* Real parent died and let us reparent to local init. */
			krg_reparent_to_local_child_reaper(task);
		}
		write_unlock_irq(&tasklist_lock);
#endif /* CONFIG_KRG_EPM */
	}

	return cookie;
}

void krg_finish_exit_notify(struct task_struct *task, int signal, void *cookie)
{
#ifdef CONFIG_KRG_EPM
	if (cookie) {
		struct children_kddm_object *parent_children_obj = cookie;
		pid_t parent_pid;

		if (task->parent == baby_sitter)
			parent_pid = task->task_obj->parent;
		else
			parent_pid = task->parent->pid;
		krg_unlock_pid_location(parent_pid);

		if (signal == DEATH_REAP) {
			/*
			 * Parent was not interested by notification, but may
			 * have been woken up in do_wait and should not see tsk
			 * as a child anymore. Remove tsk from its children kddm
			 * object before parent can access it again.
			 */
			krg_remove_child(parent_children_obj, task);
		} else {
			krg_set_child_exit_signal(parent_children_obj, task);
			krg_set_child_exit_state(parent_children_obj, task);
			krg_set_child_location(parent_children_obj, task);
		}
		krg_children_unlock(parent_children_obj);
	}
#endif /* CONFIG_KRG_EPM */

	if (task->task_obj)
		__krg_task_unlock(task);
}

void krg_release_task(struct task_struct *p)
{
#ifdef CONFIG_KRG_EPM
	krg_exit_application(p);
	krg_unhash_process(p);
	if (p->exit_state != EXIT_MIGRATION) {
#endif /* CONFIG_KRG_EPM */
		krg_task_free(p);
#ifdef CONFIG_KRG_EPM
		if (krg_action_pending(p, EPM_MIGRATE))
			/* Migration aborted because p died before */
			migration_aborted(p);
	}
#endif /* CONFIG_KRG_EPM */
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

int krg_delay_release_task(struct task_struct *task)
{
	int delayed;

	BUG_ON(!list_empty(&task->children));

	/*
	 * No need to lock tasklist since if task is current
	 * thread_group_leader() is safe
	 */
	delayed = !thread_group_leader(task) && task == current;
	if (delayed) {
		spin_lock(&tasks_to_release_lock);
		list_add_tail(&task->children, &tasks_to_release);
		spin_unlock(&tasks_to_release_lock);

		queue_work(krg_wq, &delay_release_task_work);
	}

	return delayed;
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
	bool release = false;

	krg_task_writelock(msg->zombie_pid);
	write_lock_irq(&tasklist_lock);

	zombie = find_task_by_pid_ns(msg->zombie_pid, &init_pid_ns);
	BUG_ON(!zombie);

	/* Real parent died and let us reparent zombie to local init. */
	krg_reparent_to_local_child_reaper(zombie);

	BUG_ON(zombie->exit_state != EXIT_ZOMBIE);
	BUG_ON(zombie->exit_signal == -1);
	if (!zombie->ptrace && thread_group_empty(zombie)) {
		do_notify_parent(zombie, zombie->exit_signal);
		if (task_detached(zombie)) {
			zombie->exit_state = EXIT_DEAD;
			release = true;
		}
	}

	write_unlock_irq(&tasklist_lock);
	krg_task_unlock(msg->zombie_pid);

	if (release)
		release_task(zombie);
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
