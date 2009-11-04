/*
 *  Copyright (C) 2006-2007, Pascal Gallard, Kerlabs.
 */

#define MODULE_NAME "Hotplug"

#include <linux/sched.h>
#include <linux/rwsem.h>
#include <linux/mutex.h>
#include <linux/completion.h>
#include <linux/string.h>
#include <linux/limits.h>
#include <linux/kthread.h>
#include <linux/syscalls.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/ipc.h>
#include <asm/uaccess.h>
#include <asm/ioctl.h>
#include <kerrighed/sys/types.h>
#include <kerrighed/krginit.h>
#include <kerrighed/hotplug.h>
#include <kerrighed/krgnodemask.h>

#include <kerrighed/krgflags.h>

#include <kerrighed/krg_syscalls.h>
#include <kerrighed/krg_services.h>
#include <kerrighed/workqueue.h>
#include <kerrighed/krgnodemask.h>
#include <kerrighed/namespace.h>
#include <net/krgrpc/rpc.h>
#ifdef CONFIG_KRG_KDDM
#include <kddm/kddm.h>
#endif
#ifdef CONFIG_KRG_PROC
#include <kerrighed/task.h>
#include <kerrighed/pid.h>
#endif
#ifdef CONFIG_KRG_EPM
#include <kerrighed/signal.h>
#include <kerrighed/children.h>
#endif
#ifdef CONFIG_KRG_SCHED
#include <kerrighed/scheduler/info.h>
#endif

#include "hotplug_internal.h"

#define ADVERTISE_PERIOD (2*HZ)
#define UNIVERSE_PERIOD (60*HZ)

enum {
	CLUSTER_UNDEF,
	CLUSTER_DEF,
};

static char clusters_status[KERRIGHED_MAX_CLUSTERS];

static krgnodemask_t cluster_start_nodes;
static struct cluster_start_msg {
	struct hotplug_node_set node_set;
	unsigned long seq_id;
} cluster_start_msg;
static int cluster_start_in_progress;
static struct krg_namespace *cluster_start_krg_ns;
static DEFINE_SPINLOCK(cluster_start_lock);
static DEFINE_MUTEX(cluster_start_mutex);
static DECLARE_COMPLETION(cluster_started);

#ifdef CONFIG_KRG_IPC
#define CLUSTER_INIT_OPT_CLONE_FLAGS_IPC CLONE_NEWIPC
#else
#define CLUSTER_INIT_OPT_CLONE_FLAGS_IPC 0
#endif
#ifdef CONFIG_KRG_PROC
#define CLUSTER_INIT_OPT_CLONE_FLAGS_PID CLONE_NEWPID
#else
#define CLUSTER_INIT_OPT_CLONE_FLAGS_PID 0
#endif
static unsigned long cluster_init_opt_clone_flags =
	CLUSTER_INIT_OPT_CLONE_FLAGS_IPC|CLUSTER_INIT_OPT_CLONE_FLAGS_PID;
static DEFINE_SPINLOCK(cluster_init_opt_clone_flags_lock);

static char cluster_init_helper_path[PATH_MAX];
static char *cluster_init_helper_argv[] = {
	cluster_init_helper_path,
	NULL
};
static char *cluster_init_helper_envp[] = {
	"HOME=/",
	"PATH=/sbin:/bin:/usr/sbin:/usr/bin",
	NULL
};
static struct cred *cluster_init_helper_cred;
static struct krg_namespace *cluster_init_helper_ns;
static struct completion cluster_init_helper_ready;

static struct completion krg_container_continue;
static struct completion krg_container_done;

static ssize_t isolate_uts_show(struct kobject *obj,
				struct kobj_attribute *attr,
				char *page)
{
	int isolate = !!(cluster_init_opt_clone_flags & CLONE_NEWUTS);
	return sprintf(page, "%d\n", isolate);
}

static ssize_t isolate_uts_store(struct kobject *obj,
				 struct kobj_attribute *attr,
				 const char *page, size_t count)
{
	unsigned long val = simple_strtoul(page, NULL, 0);

	spin_lock(&cluster_init_opt_clone_flags_lock);
	if (val)
		cluster_init_opt_clone_flags |= CLONE_NEWUTS;
	else
		cluster_init_opt_clone_flags &= ~CLONE_NEWUTS;
	spin_unlock(&cluster_init_opt_clone_flags_lock);

	return count;
}

static struct kobj_attribute isolate_uts_attr =
	__ATTR(isolate_uts, 0644, isolate_uts_show, isolate_uts_store);

static ssize_t isolate_ipc_show(struct kobject *obj,
				struct kobj_attribute *attr,
				char *page)
{
	int isolate = !!(cluster_init_opt_clone_flags & CLONE_NEWIPC);
	return sprintf(page, "%d\n", isolate);
}

#ifdef CONFIG_KRG_IPC
static struct kobj_attribute isolate_ipc_attr =
	__ATTR(isolate_ipc, 0444, isolate_ipc_show, NULL);
#else
static ssize_t isolate_ipc_store(struct kobject *obj,
				 struct kobj_attribute *attr,
				 const char *page, size_t count)
{
	unsigned long val = simple_strtoul(page, NULL, 0);

	spin_lock(&cluster_init_opt_clone_flags_lock);
	if (val)
		cluster_init_opt_clone_flags |= CLONE_NEWIPC;
	else
		cluster_init_opt_clone_flags &= ~CLONE_NEWIPC;
	spin_unlock(&cluster_init_opt_clone_flags_lock);

	return count;
}

static struct kobj_attribute isolate_ipc_attr =
	__ATTR(isolate_ipc, 0644, isolate_ipc_show, isolate_ipc_store);
#endif /* !CONFIG_KRG_IPC */

static ssize_t isolate_mnt_show(struct kobject *obj,
				struct kobj_attribute *attr,
				char *page)
{
	int isolate = !!(cluster_init_opt_clone_flags & CLONE_NEWNS);
	return sprintf(page, "%d\n", isolate);
}

static ssize_t isolate_mnt_store(struct kobject *obj,
				 struct kobj_attribute *attr,
				 const char *page, size_t count)
{
	unsigned long val = simple_strtoul(page, NULL, 0);

	spin_lock(&cluster_init_opt_clone_flags_lock);
	if (val)
		cluster_init_opt_clone_flags |= CLONE_NEWNS;
	else
		cluster_init_opt_clone_flags &= ~CLONE_NEWNS;
	spin_unlock(&cluster_init_opt_clone_flags_lock);

	return count;
}

static struct kobj_attribute isolate_mnt_attr =
	__ATTR(isolate_mnt, 0644, isolate_mnt_show, isolate_mnt_store);

static ssize_t isolate_pid_show(struct kobject *obj,
				struct kobj_attribute *attr,
				char *page)
{
	int isolate = !!(cluster_init_opt_clone_flags & CLONE_NEWPID);
	return sprintf(page, "%d\n", isolate);
}

#ifdef CONFIG_KRG_PROC
static struct kobj_attribute isolate_pid_attr =
	__ATTR(isolate_pid, 0444, isolate_pid_show, NULL);
#else
static ssize_t isolate_pid_store(struct kobject *obj,
				 struct kobj_attribute *attr,
				 const char *page, size_t count)
{
	unsigned long val = simple_strtoul(page, NULL, 0);

	spin_lock(&cluster_init_opt_clone_flags_lock);
	if (val)
		cluster_init_opt_clone_flags |= CLONE_NEWPID;
	else
		cluster_init_opt_clone_flags &= ~CLONE_NEWPID;
	spin_unlock(&cluster_init_opt_clone_flags_lock);

	return count;
}

static struct kobj_attribute isolate_pid_attr =
	__ATTR(isolate_pid, 0644, isolate_pid_show, isolate_pid_store);
#endif /* !CONFIG_KRG_PROC */

static ssize_t isolate_net_show(struct kobject *obj,
				struct kobj_attribute *attr,
				char *page)
{
	int isolate = !!(cluster_init_opt_clone_flags & CLONE_NEWNET);
	return sprintf(page, "%d\n", isolate);
}

static ssize_t isolate_net_store(struct kobject *obj,
				 struct kobj_attribute *attr,
				 const char *page, size_t count)
{
	unsigned long val = simple_strtoul(page, NULL, 0);

	spin_lock(&cluster_init_opt_clone_flags_lock);
	if (val)
		cluster_init_opt_clone_flags |= CLONE_NEWNET;
	else
		cluster_init_opt_clone_flags &= ~CLONE_NEWNET;
	spin_unlock(&cluster_init_opt_clone_flags_lock);

	return count;
}

static struct kobj_attribute isolate_net_attr =
	__ATTR(isolate_net, 0644, isolate_net_show, isolate_net_store);

static ssize_t isolate_user_show(struct kobject *obj,
				 struct kobj_attribute *attr,
				 char *page)
{
	int isolate = !!(cluster_init_opt_clone_flags & CLONE_NEWUSER);
	return sprintf(page, "%d\n", isolate);
}

static ssize_t isolate_user_store(struct kobject *obj,
				  struct kobj_attribute *attr,
				  const char *page, size_t count)
{
	unsigned long val = simple_strtoul(page, NULL, 0);

	spin_lock(&cluster_init_opt_clone_flags_lock);
	if (val)
		cluster_init_opt_clone_flags |= CLONE_NEWUSER;
	else
		cluster_init_opt_clone_flags &= ~CLONE_NEWUSER;
	spin_unlock(&cluster_init_opt_clone_flags_lock);

	return count;
}

static struct kobj_attribute isolate_user_attr =
	__ATTR(isolate_user, 0644, isolate_user_show, isolate_user_store);

static ssize_t cluster_init_helper_show(struct kobject *obj,
					struct kobj_attribute *attr,
					char *page)
{
	return sprintf(page, "%s\n", cluster_init_helper_path);
}

static ssize_t cluster_init_helper_store(struct kobject *obj,
					 struct kobj_attribute *attr,
					 const char *page, size_t count)
{
	if (count > sizeof(cluster_init_helper_path)
	    || (count == sizeof(cluster_init_helper_path)
		&& page[count - 1] != '\0'))
		return -ENAMETOOLONG;

	mutex_lock(&cluster_start_mutex);
	strcpy(cluster_init_helper_path, page);
	mutex_unlock(&cluster_start_mutex);

	return count;
}

static struct kobj_attribute cluster_init_helper_attr =
	__ATTR(cluster_init_helper, 0644,
	       cluster_init_helper_show, cluster_init_helper_store);

static struct attribute *attrs[] = {
	&isolate_uts_attr.attr,
	&isolate_ipc_attr.attr,
	&isolate_mnt_attr.attr,
	&isolate_pid_attr.attr,
	&isolate_net_attr.attr,
	&isolate_user_attr.attr,
	&cluster_init_helper_attr.attr,
	NULL,
};

static struct attribute_group attr_group = {
	.attrs = attrs,
};

static void krg_container_abort(int err)
{
	put_krg_ns(cluster_init_helper_ns);
	cluster_init_helper_ns = ERR_PTR(err);
	complete(&cluster_init_helper_ready);
}

void krg_ns_root_exit(struct task_struct *task)
{
	if (cluster_init_helper_ns
	    && task->nsproxy->krg_ns == cluster_init_helper_ns)
		krg_container_abort(-EAGAIN);
}

/* ns->root_task must be blocked and alive to get a reliable result */
static bool krg_container_may_conflict(struct krg_namespace *ns)
{
	struct task_struct *root_task = ns->root_task;
	struct task_struct *g, *t;
#ifndef CONFIG_KRG_PROC
	struct nsproxy *nsp;
#endif
	bool conflict = false;

	/*
	 * Check that userspace did not leak tasks in the Kerrighed container
	 * With !KRG_PROC this does not check zombies, but they won't use any
	 * conflicting resource.
	 */
	rcu_read_lock();
	read_lock(&tasklist_lock);
	do_each_thread(g, t) {
		if (t == root_task)
			continue;

#ifdef CONFIG_KRG_PROC
		if (task_active_pid_ns(t)->krg_ns_root == ns->root_pid_ns)
#else
		nsp = task_nsproxy(t);
		if (nsp && nsp->krg_ns == ns)
#endif
		{
			conflict = true;
			break;
		}
	} while_each_thread(g, t);
	read_unlock(&tasklist_lock);
	rcu_read_unlock();
	if (conflict)
		return conflict;

#ifdef CONFIG_KRG_IPC
	/*
	 * Check that userspace did not leak IPCs in the Kerrighed
	 * container
	 */
	if (root_task->nsproxy->ipc_ns != ns->root_ipc_ns
	    || ipc_used(ns->root_ipc_ns))
		conflict = true;
#endif

	return conflict;
}

static int krg_container_cleanup(struct krg_namespace *ns)
{
#ifdef CONFIG_KRG_IPC
	cleanup_ipc_objects ();
#endif

	return 0;
}

static void krg_container_run(void)
{
	complete(&cluster_init_helper_ready);

	wait_for_completion(&krg_container_continue);
	complete(&krg_container_done);
}

static int krg_container_init(void *arg)
{
	struct krg_namespace *ns;
	int err;

	/* Unblock all signals */
	spin_lock_irq(&current->sighand->siglock);
	flush_signal_handlers(current, 1);
	sigemptyset(&current->blocked);
	recalc_sigpending();
	spin_unlock_irq(&current->sighand->siglock);

	/* Install the credentials */
	commit_creds(cluster_init_helper_cred);
	cluster_init_helper_cred = NULL;

	/* We can run anywhere, unlike our parent (a krgrpc) */
	set_cpus_allowed_ptr(current, cpu_all_mask);

	/*
	 * Our parent is a krgrpc, which runs with elevated scheduling priority.
	 * Avoid propagating that into the userspace child.
	 */
	set_user_nice(current, 0);

	BUG_ON(cluster_init_helper_ns);
	ns = current->nsproxy->krg_ns;
	if (!ns) {
		cluster_init_helper_ns = ERR_PTR(-EPERM);
		complete(&cluster_init_helper_ready);
		return 0;
	}
	get_krg_ns(ns);
	cluster_init_helper_ns = ns;

	err = kernel_execve(cluster_init_helper_path,
			    cluster_init_helper_argv,
			    cluster_init_helper_envp);
	BUG_ON(!err);
	printk(KERN_ERR
	       "kerrighed: Kerrighed container userspace init failed: err=%d\n",
	       err);

	krg_container_abort(err);

	return 0;
}

static int __create_krg_container(void *arg)
{
	unsigned long clone_flags;
	int ret;

	ret = krg_set_cluster_creator((void *)1);
	if (ret)
		goto err;
	clone_flags = cluster_init_opt_clone_flags|SIGCHLD;
	ret = kernel_thread(krg_container_init, NULL, clone_flags);
	krg_set_cluster_creator(NULL);
	if (ret < 0)
		goto err;

	return 0;

err:
	put_cred(cluster_init_helper_cred);
	cluster_init_helper_cred = NULL;
	cluster_init_helper_ns = ERR_PTR(ret);
	complete(&cluster_init_helper_ready);
	return ret;
}

static
struct krg_namespace *create_krg_container(struct krg_namespace *ns)
{
	struct task_struct *t;

	if (ns) {
		put_krg_ns(ns);
		return NULL;
	}

	BUG_ON(cluster_init_helper_ns);
	init_completion(&cluster_init_helper_ready);

	BUG_ON(cluster_init_helper_cred);
	cluster_init_helper_cred = prepare_usermodehelper_creds();
	if (!cluster_init_helper_cred)
		return NULL;

	t = kthread_run(__create_krg_container, NULL, "krg_init_helper");
	if (IS_ERR(t)) {
		put_cred(cluster_init_helper_cred);
		cluster_init_helper_cred = NULL;
		return NULL;
	}

	wait_for_completion(&cluster_init_helper_ready);
	if (IS_ERR(cluster_init_helper_ns)) {
		ns = NULL;
	} else {
		ns = cluster_init_helper_ns;
		BUG_ON(!ns);
	}
	cluster_init_helper_ns = NULL;

	return ns;
}

static void handle_cluster_start(struct rpc_desc *desc, void *data, size_t size)
{
	struct cluster_start_msg *msg = data;
	struct krg_namespace *ns = find_get_krg_ns();
	int master = rpc_desc_get_client(desc) == kerrighed_node_id;
	char *page;
	int ret = 0;
	int err;

	mutex_lock(&cluster_start_mutex);

	if (master) {
		err = -EPIPE;
		spin_lock(&cluster_start_lock);
		if (cluster_start_in_progress
		    && msg->seq_id == cluster_start_msg.seq_id
		    && ns == cluster_start_krg_ns)
			err = 0;
		spin_unlock(&cluster_start_lock);
		if (err)
			goto cancel;
	}

	if (kerrighed_subsession_id != -1){
		printk("WARNING: Rq to add me in a cluster (%d) when I'm already in one (%d)\n",
		       msg->node_set.subclusterid, kerrighed_subsession_id);
		goto cancel;
	}

	if (!master) {
		init_completion(&krg_container_continue);
		ns = create_krg_container(ns);
		if (!ns)
			goto cancel;
	}

	err = rpc_pack_type(desc, ret);
	if (err)
		goto cancel;
	err = rpc_unpack_type(desc, ret);
	if (err)
		goto cancel;

	kerrighed_subsession_id = msg->node_set.subclusterid;
	__nodes_add(&msg->node_set);

	down_write(&kerrighed_init_sem);
	hooks_start();
	up_write(&kerrighed_init_sem);

	rpc_enable_all();

	SET_KERRIGHED_CLUSTER_FLAGS(KRGFLAGS_RUNNING);
	SET_KERRIGHED_NODE_FLAGS(KRGFLAGS_RUNNING);
	clusters_status[kerrighed_subsession_id] = CLUSTER_DEF;

	page = (char *)__get_free_page(GFP_KERNEL);
	if (page) {
		ret = krgnodelist_scnprintf(page, PAGE_SIZE, msg->node_set.v);
		BUG_ON(ret >= PAGE_SIZE);
		printk("Kerrighed is running on %d nodes: %s\n",
		       krgnodes_weight(msg->node_set.v), page);
		free_page((unsigned long)page);
	} else {
		printk("Kerrighed is running on %d nodes\n", num_online_krgnodes());
	}
	complete_all(&cluster_started);

	if (!master) {
		init_completion(&krg_container_done);
		complete(&krg_container_continue);
		wait_for_completion(&krg_container_done);
	}

out:
	mutex_unlock(&cluster_start_mutex);
	if (ns)
		put_krg_ns(ns);
	return;

cancel:
	rpc_cancel(desc);
	goto out;
}

static void cluster_start_worker(struct work_struct *work)
{
	struct rpc_desc *desc;
	char *page;
	kerrighed_node_t node;
	int ret;
	int err = -ENOMEM;

	page = (char *)__get_free_page(GFP_KERNEL);
	if (!page)
		goto out;

	ret = krgnodelist_scnprintf(page, PAGE_SIZE, cluster_start_nodes);
	BUG_ON(ret >= PAGE_SIZE);
	printk("kerrighed: Cluster start on nodes %s ...\n", page);

	free_page((unsigned long)page);

	desc = rpc_begin_m(CLUSTER_START, &cluster_start_nodes);
	if (!desc)
		goto out;
	err = rpc_pack_type(desc, cluster_start_msg);
	if (err)
		goto end;
	for_each_krgnode_mask(node, cluster_start_nodes) {
		err = rpc_unpack_type_from(desc, node, ret);
		if (err)
			goto cancel;
	}
	ret = 0;
	err = rpc_pack_type(desc, ret);
	if (err)
		goto cancel;
	/*
	 * We might wait for a last ack from the nodes, but there would be no
	 * gain since local cluster start is currently not allowed to fail and
	 * transactions will be queued until the nodes are ready.
	 */
end:
	rpc_end(desc, 0);
out:
	if (err)
		printk(KERN_ERR "kerrighed: Cluster start failed! err=%d\n",
		       err);
	else
		printk("kerrighed: Cluster start succeeded.\n");
	spin_lock(&cluster_start_lock);
	cluster_start_in_progress = 0;
	put_krg_ns(cluster_start_krg_ns);
	spin_unlock(&cluster_start_lock);
	return;
cancel:
	rpc_cancel(desc);
	if (err > 0)
		err = -EPIPE;
	goto end;
}

static DECLARE_WORK(cluster_start_work, cluster_start_worker);

int do_cluster_start(const struct hotplug_node_set *node_set,
		     struct krg_namespace *ns)
{
	int r = -EALREADY;

	spin_lock(&cluster_start_lock);
	if (!cluster_start_in_progress) {
		r = -EPERM;
		if (ns) {
			if (cluster_start_msg.seq_id == ULONG_MAX) {
				printk(KERN_WARNING "kerrighed: "
				       "Max number of cluster start attempts "
				       "reached! You should reboot host.\n");
			} else {
				r = 0;
				get_krg_ns(ns);
				cluster_start_krg_ns = ns;
				krgnodes_copy(cluster_start_nodes, node_set->v);
				cluster_start_msg.seq_id++;
				krgnodes_or(cluster_start_msg.node_set.v,
					    node_set->v,
					    krgnode_online_map);
				cluster_start_in_progress = 1;
				queue_work(krg_wq, &cluster_start_work);
			}
		}
	}
	spin_unlock(&cluster_start_lock);

	return r;
}

static void do_cluster_wait_for_start(void)
{
	wait_for_completion(&cluster_started);
}

static int cluster_start(void *arg)
{
	int r = 0;
	struct __hotplug_node_set __node_set;
	struct hotplug_node_set node_set;
	struct krg_namespace *ns;

	if (copy_from_user(&__node_set, arg, sizeof(__node_set))) {
		r = -EFAULT;
	} else {
		node_set.subclusterid = __node_set.subclusterid;

		r = krgnodemask_copy_from_user(&node_set.v, &__node_set.v);
		if (!r) {
			ns = current->nsproxy->krg_ns;
			r = do_cluster_start(&node_set, ns);
		}
	}
	if (!r)
		do_cluster_wait_for_start();

	return r;
}

void krg_cluster_autostart(void)
{
	struct hotplug_node_set node_set;
	static int already_start = 0;
	struct krg_namespace *ns;
	int i, nb;

	if (likely(already_start)
	   || kerrighed_nb_nodes_min < 0)
		return;

	node_set.subclusterid = 0;
	nb = 0;

	krgnodes_clear(node_set.v);
	for (i=0; i<KERRIGHED_MAX_NODES; i++) {
		if ((universe[i].state == 0
		    && i != kerrighed_node_id)
		    || universe[i].subid != -1)
			continue;

		if (i < kerrighed_node_id)
			return;

		nb++;
		krgnode_set(i, node_set.v);
	}

	if (nb >= kerrighed_nb_nodes_min) {
		already_start = 1;
		ns = find_get_krg_ns();
		do_cluster_start(&node_set, ns);
		if (ns)
			put_krg_ns(ns);
	}
}

static int cluster_wait_for_start(void __user *arg)
{
	do_cluster_wait_for_start();
	return 0;
}

static int node_ready(void __user *arg)
{
	struct krg_namespace *ns = current->nsproxy->krg_ns;

	if (!ns || ns != cluster_init_helper_ns)
		return -EPERM;

	if (krg_container_may_conflict(ns))
		return -EBUSY;
	if (krg_container_cleanup(ns))
		return -EBUSY;

	krg_container_run();
	return 0;
}

static int cluster_restart(void *arg)
{
	int unused;

	rpc_async_m(NODE_FAIL, &krgnode_online_map,
		    &unused, sizeof(unused));
	
	return 0;
}

static int cluster_stop(void *arg)
{
	int unused;
	
	rpc_async_m(NODE_FAIL, &krgnode_online_map,
		    &unused, sizeof(unused));
	
	return 0;
}

static int cluster_status(void __user *arg)
{
	int r = -EFAULT;
	struct hotplug_clusters __user *uclusters = arg;
	int bcl;

	if (!access_ok(VERIFY_WRITE, uclusters, sizeof(*uclusters)))
		goto out;

	for (bcl = 0; bcl < KERRIGHED_MAX_CLUSTERS; bcl++)
		if (__put_user(clusters_status[bcl], &uclusters->clusters[bcl]))
			goto out;
	r = 0;

out:
	return r;
}

static int cluster_nodes(void __user *arg)
{
	int r = -EFAULT;
	struct hotplug_nodes __user *nodes_arg = arg;
	char __user *unodes;
	char state;
	int bcl;

	if (get_user(unodes, &nodes_arg->nodes))
		goto out;

	if (!access_ok(VERIFY_WRITE, unodes, KERRIGHED_MAX_NODES))
		goto out;

	for (bcl = 0; bcl < KERRIGHED_MAX_NODES; bcl++) {
		state = 0;
		if (krgnode_present(bcl) && universe[bcl].state)
			state = 1;
		if (__put_user(state, &unodes[bcl]))
			goto out;
	}
	r = 0;

out:
	return r;
}

int krgnodemask_copy_from_user(krgnodemask_t *dstp, __krgnodemask_t *srcp)
{
	int r;

	r = find_next_bit(srcp->bits, KERRIGHED_HARD_MAX_NODES,
			  KERRIGHED_MAX_NODES);

	if (r >= KERRIGHED_MAX_NODES && r < KERRIGHED_HARD_MAX_NODES)
		return -EINVAL;

	bitmap_copy(dstp->bits, srcp->bits, KERRIGHED_MAX_NODES);

	return 0;
}

int hotplug_cluster_init(void)
{
	int bcl;

	if (sysfs_create_group(krghotplugsys, &attr_group))
		panic("Couldn't initialize /sys/kerrighed/hotplug!\n");

	for (bcl = 0; bcl < KERRIGHED_MAX_CLUSTERS; bcl++) {
		clusters_status[bcl] = CLUSTER_UNDEF;
	}

	rpc_register_void(CLUSTER_START, handle_cluster_start, 0);
	
	register_proc_service(KSYS_HOTPLUG_START, cluster_start);
	register_proc_service(KSYS_HOTPLUG_READY, node_ready);
	register_proc_service(KSYS_HOTPLUG_WAIT_FOR_START,
			      cluster_wait_for_start);
	register_proc_service(KSYS_HOTPLUG_SHUTDOWN, cluster_stop);
	register_proc_service(KSYS_HOTPLUG_RESTART, cluster_restart);
	register_proc_service(KSYS_HOTPLUG_STATUS, cluster_status);
	register_proc_service(KSYS_HOTPLUG_NODES, cluster_nodes);

	return 0;
}

void hotplug_cluster_cleanup(void)
{
}
