/*
 * Pid namespaces
 *
 * Authors:
 *    (C) 2007 Pavel Emelyanov <xemul@openvz.org>, OpenVZ, SWsoft Inc.
 *    (C) 2007 Sukadev Bhattiprolu <sukadev@us.ibm.com>, IBM
 *     Many thanks to Oleg Nesterov for comments and help
 *
 */

#include <linux/pid.h>
#include <linux/pid_namespace.h>
#include <linux/syscalls.h>
#include <linux/err.h>
#include <linux/acct.h>
#ifdef CONFIG_KRG_PROC
#include <linux/module.h>
#include <kerrighed/namespace.h>
#endif

#define BITS_PER_PAGE		(PAGE_SIZE*8)

struct pid_cache {
	int nr_ids;
	char name[16];
	struct kmem_cache *cachep;
	struct list_head list;
};

static LIST_HEAD(pid_caches_lh);
static DEFINE_MUTEX(pid_caches_mutex);
static struct kmem_cache *pid_ns_cachep;

/*
 * creates the kmem cache to allocate pids from.
 * @nr_ids: the number of numerical ids this pid will have to carry
 */

static struct kmem_cache *create_pid_cachep(int nr_ids)
{
	struct pid_cache *pcache;
	struct kmem_cache *cachep;

	mutex_lock(&pid_caches_mutex);
	list_for_each_entry(pcache, &pid_caches_lh, list)
		if (pcache->nr_ids == nr_ids)
			goto out;

	pcache = kmalloc(sizeof(struct pid_cache), GFP_KERNEL);
	if (pcache == NULL)
		goto err_alloc;

	snprintf(pcache->name, sizeof(pcache->name), "pid_%d", nr_ids);
	cachep = kmem_cache_create(pcache->name,
			sizeof(struct pid) + (nr_ids - 1) * sizeof(struct upid),
			0, SLAB_HWCACHE_ALIGN, NULL);
	if (cachep == NULL)
		goto err_cachep;

	pcache->nr_ids = nr_ids;
	pcache->cachep = cachep;
	list_add(&pcache->list, &pid_caches_lh);
out:
	mutex_unlock(&pid_caches_mutex);
	return pcache->cachep;

err_cachep:
	kfree(pcache);
err_alloc:
	mutex_unlock(&pid_caches_mutex);
	return NULL;
}

#ifndef CONFIG_KRG_EPM
static
#endif
struct pid_namespace *create_pid_namespace(unsigned int level)
{
	struct pid_namespace *ns;
	int i;

	ns = kmem_cache_zalloc(pid_ns_cachep, GFP_KERNEL);
	if (ns == NULL)
		goto out;

	ns->pidmap[0].page = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!ns->pidmap[0].page)
		goto out_free;

	ns->pid_cachep = create_pid_cachep(level + 1);
	if (ns->pid_cachep == NULL)
		goto out_free_map;

	kref_init(&ns->kref);
	ns->level = level;

	set_bit(0, ns->pidmap[0].page);
	atomic_set(&ns->pidmap[0].nr_free, BITS_PER_PAGE - 1);

	for (i = 1; i < PIDMAP_ENTRIES; i++)
		atomic_set(&ns->pidmap[i].nr_free, BITS_PER_PAGE);

	return ns;

out_free_map:
	kfree(ns->pidmap[0].page);
out_free:
	kmem_cache_free(pid_ns_cachep, ns);
out:
	return ERR_PTR(-ENOMEM);
}

static void destroy_pid_namespace(struct pid_namespace *ns)
{
	int i;

#ifdef CONFIG_KRG_PROC
	if (ns->krg_ns_root && ns->krg_ns_root != ns)
		put_pid_ns(ns->krg_ns_root);
#endif
	for (i = 0; i < PIDMAP_ENTRIES; i++)
		kfree(ns->pidmap[i].page);
	kmem_cache_free(pid_ns_cachep, ns);
}

struct pid_namespace *copy_pid_ns(unsigned long flags, struct pid_namespace *old_ns)
{
	struct pid_namespace *new_ns;

	BUG_ON(!old_ns);
	new_ns = get_pid_ns(old_ns);
	if (!(flags & CLONE_NEWPID))
		goto out;

	new_ns = ERR_PTR(-EINVAL);
	if (flags & CLONE_THREAD)
		goto out_put;

	new_ns = create_pid_namespace(old_ns->level + 1);
	if (!IS_ERR(new_ns))
#ifdef CONFIG_KRG_PROC
	{
		new_ns->global = old_ns->global;
		new_ns->global |= current->create_krg_ns;
		if (old_ns->krg_ns_root)
			get_pid_ns(old_ns->krg_ns_root);
		new_ns->krg_ns_root = old_ns->krg_ns_root;
		new_ns->parent = get_pid_ns(old_ns);
	}
#else
		new_ns->parent = get_pid_ns(old_ns);
#endif

out_put:
	put_pid_ns(old_ns);
out:
	return new_ns;
}

void free_pid_ns(struct kref *kref)
{
	struct pid_namespace *ns, *parent;

	ns = container_of(kref, struct pid_namespace, kref);

	parent = ns->parent;
	destroy_pid_namespace(ns);

	if (parent != NULL)
		put_pid_ns(parent);
}
#ifdef CONFIG_KRG_PROC
EXPORT_SYMBOL(free_pid_ns);
#endif

void zap_pid_ns_processes(struct pid_namespace *pid_ns)
{
	int nr;
	int rc;
	struct task_struct *task;

	/*
	 * The last thread in the cgroup-init thread group is terminating.
	 * Find remaining pid_ts in the namespace, signal and wait for them
	 * to exit.
	 *
	 * Note:  This signals each threads in the namespace - even those that
	 * 	  belong to the same thread group, To avoid this, we would have
	 * 	  to walk the entire tasklist looking a processes in this
	 * 	  namespace, but that could be unnecessarily expensive if the
	 * 	  pid namespace has just a few processes. Or we need to
	 * 	  maintain a tasklist for each pid namespace.
	 *
	 */
	read_lock(&tasklist_lock);
	nr = next_pidmap(pid_ns, 1);
	while (nr > 0) {
		rcu_read_lock();

		/*
		 * Use force_sig() since it clears SIGNAL_UNKILLABLE ensuring
		 * any nested-container's init processes don't ignore the
		 * signal
		 */
		task = pid_task(find_vpid(nr), PIDTYPE_PID);
		if (task)
			force_sig(SIGKILL, task);

		rcu_read_unlock();

		nr = next_pidmap(pid_ns, nr);
	}
	read_unlock(&tasklist_lock);

	do {
		clear_thread_flag(TIF_SIGPENDING);
		rc = sys_wait4(-1, NULL, __WALL, NULL);
	} while (rc != -ECHILD);

	acct_exit_ns(pid_ns);
	return;
}

#ifdef CONFIG_KRG_PROC
struct pid_namespace *find_get_krg_pid_ns(void)
{
	struct krg_namespace *krg_ns = find_get_krg_ns();
	struct pid_namespace *ns = get_pid_ns(krg_ns->root_nsproxy.pid_ns);
	put_krg_ns(krg_ns);
	return ns;
}
EXPORT_SYMBOL(find_get_krg_pid_ns);
#endif

static __init int pid_namespaces_init(void)
{
	pid_ns_cachep = KMEM_CACHE(pid_namespace, SLAB_PANIC);
	return 0;
}

__initcall(pid_namespaces_init);
