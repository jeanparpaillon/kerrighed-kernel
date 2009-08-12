#ifndef __KRG_NAMESPACE_H__
#define __KRG_NAMESPACE_H__

#include <linux/rcupdate.h>
#include <asm/atomic.h>

struct task_struct;
struct nsproxy;

struct krg_namespace {
	atomic_t count;
	struct uts_namespace *root_uts_ns;
	struct ipc_namespace *root_ipc_ns;
	struct mnt_namespace *root_mnt_ns;
	struct pid_namespace *root_pid_ns;
	struct net	     *root_net_ns;
	struct user_namespace *root_user_ns;
	struct task_struct *root_task;
	struct rcu_head rcu;
};

int copy_krg_ns(struct task_struct *task, struct nsproxy *new);
void free_krg_ns(struct krg_namespace *ns);

struct krg_namespace *find_get_krg_ns(void);

static inline void get_krg_ns(struct krg_namespace *ns)
{
	atomic_inc(&ns->count);
}

static inline void put_krg_ns(struct krg_namespace *ns)
{
	if (atomic_dec_and_test(&ns->count))
		free_krg_ns(ns);
}

#endif /* __KRG_NAMESPACE_H__ */
