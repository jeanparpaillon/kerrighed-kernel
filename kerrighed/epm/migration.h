#ifndef __MIGRATION_H__
#define __MIGRATION_H__

#include <linux/types.h>
#include <kerrighed/sys/types.h>

int sys_migrate_process(pid_t tgid, kerrighed_node_t dest_node);
int sys_migrate_thread(pid_t pid, kerrighed_node_t dest_node);

#endif /* __MIGRATION_H__ */
