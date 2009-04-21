#ifndef __KRG_EXIT_H__
#define __KRG_EXIT_H__

#ifdef CONFIG_KRG_EPM

#include <linux/types.h>
#include <kerrighed/sys/types.h>

struct siginfo;
struct rusage;

/* Used by kcb_do_wait */
int krg_wait_task_zombie(pid_t pid, kerrighed_node_t zombie_location,
			 int noreap,
			 struct siginfo __user *infop,
			 int __user *stat_addr, struct rusage __user *ru);
/* Used by remote (zombie) child reparenting */
void notify_remote_child_reaper(pid_t zombie_pid,
				kerrighed_node_t zombie_location);

#endif /* CONFIG_KRG_EPM */

#endif /* __KRG_EXIT_H__ */
