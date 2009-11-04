#ifndef __EPM_PID_H__
#define __EPM_PID_H__

#include <linux/types.h>
#include <kerrighed/sys/types.h>

/* Used by checkpoint/restart */
int reserve_pid(pid_t pid);
int krg_pid_link_task(pid_t pid);
int __krg_pid_link_task(pid_t pid);
int cancel_pid_reservation(pid_t pid);

void pid_wait_quiescent(void);

struct hotplug_context;

int pidmap_map_alloc(kerrighed_node_t node);
int pidmap_map_add(struct hotplug_context *ctx);
int pidmap_map_remove_local(struct hotplug_context *ctx);

#endif /* __EPM_PID_H__ */
