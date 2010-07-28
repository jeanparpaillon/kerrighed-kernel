/*
 *  Migration interface API.
 *  @file migration.h
 *
 *  Implementation of migration functions.
 *
 *  @author Geoffroy Vallée
 */

#ifndef __KRG_MIGRATION_H__
#define __KRG_MIGRATION_H__

#include <linux/types.h>
#include <kerrighed/sys/types.h>

struct migration_infos_struct {
	kerrighed_node_t destination_node_id;
	union {
		pid_t process_to_migrate;
		pid_t thread_to_migrate;
	};
};

typedef struct migration_infos_struct migration_infos_t;

#ifdef CONFIG_KRG_EPM

#ifdef CONFIG_KRG_SCHED
#include <linux/notifier.h>

extern struct atomic_notifier_head kmh_migration_send_start;
extern struct atomic_notifier_head kmh_migration_send_end;
extern struct atomic_notifier_head kmh_migration_recv_start;
extern struct atomic_notifier_head kmh_migration_recv_end;
extern struct atomic_notifier_head kmh_migration_aborted;
#endif

struct task_struct;

int __may_migrate(struct task_struct *task);
int may_migrate(struct task_struct *task);

enum migration_scope {
	MIGR_THREAD,		/* A single task */
	MIGR_LOCAL_PROCESS,	/* All local threads of a thread group */
	MIGR_GLOBAL_PROCESS,	/* All threads (even those
				 * running on other nodes) of a thread group */
};

int __migrate_linux_threads(struct task_struct *task_to_migrate,
			    enum migration_scope scope,
			    kerrighed_node_t dest_node);
int migrate_linux_threads(pid_t pid,
			  enum migration_scope scope,
			  kerrighed_node_t dest_node);

/* Used by krg_release_task() */
void migration_aborted(struct task_struct *tsk);

#endif /* CONFIG_KRG_EPM */

#endif /* __KRG_MIGRATION_H__ */
