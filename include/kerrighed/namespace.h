#ifndef __KRG_NAMESPACE_H__
#define __KRG_NAMESPACE_H__

#include <linux/nsproxy.h>
#include <linux/completion.h>
#include <linux/rcupdate.h>
#include <linux/workqueue.h>
#include <asm/atomic.h>

struct task_struct;
struct rpc_communicator;

struct krg_namespace {
	atomic_t count;
	struct nsproxy root_nsproxy;
	struct user_namespace *root_user_ns;
	struct task_struct *root_task;
	struct rpc_communicator *rpc_comm;
	struct completion root_task_in_exit;
	struct completion root_task_continue_exit;
	struct rcu_head rcu;
	struct work_struct free_work;
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

bool can_create_krg_ns(unsigned long flags);

void krg_ns_root_exit(struct krg_namespace *ns);

#endif /* __KRG_NAMESPACE_H__ */
