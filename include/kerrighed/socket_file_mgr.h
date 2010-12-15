
#ifndef __SOCKET_FILE_MGR_H__
#define __SOCKET_FILE_MGR_H__

#include <kddm/kddm_types.h>
#include <kerrighed/action.h>
#include <kerrighed/ghost.h>

extern struct dvfs_mobility_operations dvfs_mobility_sock_ops;

int socket_file_faf_policy(struct epm_action *action, struct task_struct *task,
			   int index, struct file *file);
int socket_file_export(struct epm_action *action, ghost_t *ghost, struct task_struct *task,
		       int index, struct file *file);
int socket_file_import(struct epm_action *action, ghost_t *ghost, struct task_struct *task,
		       struct file **returned_file);

int krgip_migration_debug(int revert);

#endif
