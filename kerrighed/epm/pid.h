#ifndef __EPM_PID_H__
#define __EPM_PID_H__

#include <linux/types.h>
#include <kerrighed/sys/types.h>

/* Used by checkpoint/restart */
int reserve_pid(long app_id, pid_t pid);
int krg_pid_link_task(pid_t pid);
int __krg_pid_link_task(pid_t pid);
int end_pid_reservation(pid_t pid);

void pid_wait_quiescent(void);

int pidmap_map_alloc(kerrighed_node_t node);

#endif /* __EPM_PID_H__ */
