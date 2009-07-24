#ifndef __KDDM_DEBUG_H__
#define __KDDM_DEBUG_H__

#ifdef CONFIG_KRG_DEBUG

#include <linux/unique_id.h>
#include <linux/types.h>

struct kddm_log {
	char frozen_count;
	char sleeper_count;
	char node;
	char dummy;
	pid_t pid;
	long req_id;
	unique_id_t set_id;
	unsigned long obj_id;
	unsigned long fct_addr;
	unsigned long data;
	int dbg_id;
	struct kddm_log *next;
};

extern struct kddm_log *kddm_log_head, *kddm_log_tail;
extern spinlock_t kddm_log_lock;
extern atomic_t nr_kddm_logs;

extern void (*kh_kddm_print_log)(struct kddm_log *log, char *buffer);
extern void (*kh_print_proc_kddm_info)(struct task_struct *task);
extern int (*kh_kddm_display_obj)(int ns_id, long set_id, long objid);
#endif /* CONFIG_KRG_DEBUG */

#endif /* __KDDM_DEBUG_H__ */
