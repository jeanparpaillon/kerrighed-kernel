#ifndef __KRG_SCHEDULER_INFO_H__
#define __KRG_SCHEDULER_INFO_H__

#ifdef CONFIG_KRG_SCHED

#include <linux/list.h>

struct module;
struct task_struct;
struct epm_action;
struct ghost;

struct krg_sched_module_info_type {
	struct list_head list;		/* reserved for krg_sched_info */
	struct list_head instance_head;	/* subsystem internal */
	const char *name;
	struct module *owner;
	/* can block */
	struct krg_sched_module_info *(*copy)(struct task_struct *,
					      struct krg_sched_module_info *);
	/* may be called from interrupt context */
	void (*free)(struct krg_sched_module_info *);
	/* can block */
	int (*export)(struct epm_action *, struct ghost *,
		      struct krg_sched_module_info *);
	/* can block */
	struct krg_sched_module_info *(*import)(struct epm_action *,
						struct ghost *,
						struct task_struct *);
};

/* struct to include in module specific task krg_sched_info struct */
/* modification is reserved for krg_sched_info subsystem internal */
struct krg_sched_module_info {
	struct list_head info_list;
	struct list_head instance_list;
	struct krg_sched_module_info_type *type;
};

int krg_sched_module_info_register(struct krg_sched_module_info_type *type);
/*
 * must only be called at module unloading (See comment in
 * krg_sched_info_copy())
 */
void krg_sched_module_info_unregister(struct krg_sched_module_info_type *type);
/* Must be called under rcu_read_lock() */
struct krg_sched_module_info *
krg_sched_module_info_get(struct task_struct *task,
			  struct krg_sched_module_info_type *type);

/* fork() / exit() */
extern int krg_sched_info_copy(struct task_struct *tsk);
extern void krg_sched_info_free(struct task_struct *tsk);

#endif /* CONFIG_KRG_SCHED */

#endif /* __KRG_SCHEDULER_INFO_H__ */
