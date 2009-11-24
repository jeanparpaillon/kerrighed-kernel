/*
 *  kerrighed/hotplug/namespace.c
 *
 *  Copyright (C) 2009 Louis Rilling - Kerlabs
 */

#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/completion.h>
#include <linux/nsproxy.h>
#include <linux/utsname.h>
#include <linux/ipc_namespace.h>
#include <linux/mnt_namespace.h>
#include <linux/pid_namespace.h>
#include <linux/user_namespace.h>
#include <net/net_namespace.h>
#include <kerrighed/namespace.h>
#include <kerrighed/krg_services.h>
#include <kerrighed/krg_syscalls.h>

static struct krg_namespace *krg_ns;
static DEFINE_SPINLOCK(krg_ns_lock);

int copy_krg_ns(struct task_struct *task, struct nsproxy *new)
{
	struct krg_namespace *ns = task->nsproxy->krg_ns;
	struct user_namespace *user_ns = __task_cred(task)->user->user_ns;
	int retval = 0;

	if (!ns && current->create_krg_ns) {
		ns = kmalloc(sizeof(*ns), GFP_KERNEL);

		spin_lock_irq(&krg_ns_lock);
		/* Only one krg_ns can live at once. */
		if (!krg_ns) {
			if (ns) {
				atomic_set(&ns->count, 1);

				atomic_set(&ns->root_nsproxy.count, 1);
				get_uts_ns(new->uts_ns);
				ns->root_nsproxy.uts_ns = new->uts_ns;
				get_ipc_ns(new->ipc_ns);
				ns->root_nsproxy.ipc_ns = new->ipc_ns;
				get_mnt_ns(new->mnt_ns);
				ns->root_nsproxy.mnt_ns = new->mnt_ns;
				get_pid_ns(new->pid_ns);
				ns->root_nsproxy.pid_ns = new->pid_ns;
				get_net(new->net_ns);
				ns->root_nsproxy.net_ns = new->net_ns;
				ns->root_nsproxy.krg_ns = ns;

				get_user_ns(user_ns);
				ns->root_user_ns = user_ns;

				get_task_struct(task);
				ns->root_task = task;
				init_completion(&ns->root_task_in_exit);
				init_completion(&ns->root_task_continue_exit);

#ifdef CONFIG_KRG_PROC
				BUG_ON(ns->root_nsproxy.pid_ns->krg_ns);
				ns->root_nsproxy.pid_ns->krg_ns = ns;
#endif

				ns->rpc_comm = NULL;

				rcu_assign_pointer(krg_ns, ns);
			} else {
				retval = -ENOMEM;
			}
		} else {
			kfree(ns);
			ns = NULL;
		}
		spin_unlock_irq(&krg_ns_lock);
	} else if (ns) {
		get_krg_ns(ns);
	}

	new->krg_ns = ns;

	return retval;
}

static void __delayed_free_krg_ns(struct work_struct *work)
{
	struct krg_namespace *ns;

	ns = container_of(work, struct krg_namespace, free_work);

	BUG_ON(atomic_read(&ns->root_nsproxy.count) != 1);
	if (ns->root_nsproxy.uts_ns)
		put_uts_ns(ns->root_nsproxy.uts_ns);
	if (ns->root_nsproxy.ipc_ns)
		put_ipc_ns(ns->root_nsproxy.ipc_ns);
	if (ns->root_nsproxy.mnt_ns)
		put_mnt_ns(ns->root_nsproxy.mnt_ns);
	if (ns->root_nsproxy.pid_ns)
		put_pid_ns(ns->root_nsproxy.pid_ns);
	if (ns->root_nsproxy.net_ns)
		put_net(ns->root_nsproxy.net_ns);
	if (ns->root_user_ns)
		put_user_ns(ns->root_user_ns);

	put_task_struct(ns->root_task);

	kfree(ns);
}

static void delayed_free_krg_ns(struct rcu_head *rcu)
{
	struct krg_namespace *ns = container_of(rcu, struct krg_namespace, rcu);

	INIT_WORK(&ns->free_work, __delayed_free_krg_ns);
	schedule_work(&ns->free_work);
}

void free_krg_ns(struct krg_namespace *ns)
{
	unsigned long flags;

	BUG_ON(ns->rpc_comm);

	spin_lock_irqsave(&krg_ns_lock, flags);
	BUG_ON(ns != krg_ns);
	rcu_assign_pointer(krg_ns, NULL);
	spin_unlock_irqrestore(&krg_ns_lock, flags);

	call_rcu(&ns->rcu, delayed_free_krg_ns);
}

struct krg_namespace *find_get_krg_ns(void)
{
	struct krg_namespace *ns;

	rcu_read_lock();
	ns = rcu_dereference(krg_ns);
	if (ns)
		if (!atomic_add_unless(&ns->count, 1, 0))
			ns = NULL;
	rcu_read_unlock();

	return ns;
}

bool can_create_krg_ns(unsigned long flags)
{
	return current->create_krg_ns
#ifdef CONFIG_KRG_IPC
		&& (flags & CLONE_NEWIPC)
#endif
#ifdef CONFIG_KRG_PROC
		&& (flags & CLONE_NEWPID)
#endif
		;
}

int krg_set_cluster_creator(void __user *arg)
{
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	current->create_krg_ns = !!arg;
	return 0;
}

int hotplug_namespace_init(void)
{
	return __register_proc_service(KSYS_HOTPLUG_SET_CREATOR,
				       krg_set_cluster_creator, false);
}
