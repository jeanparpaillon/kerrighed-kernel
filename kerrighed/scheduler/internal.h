#ifndef __SCHEDULER_INTERNAL_H__
#define __SCHEDULER_INTERNAL_H__

#include <linux/configfs.h>

struct hotplug_context;

#define PROBES_NAME "probes"
#define SCHEDULERS_NAME "schedulers"

extern struct configfs_subsystem krg_scheduler_subsys;

/**
 * Checks that item is a probe source subdir of a probe.
 * @author Louis Rilling, Marko Novak
 *
 * @param item		pointer to the config_item to check
 */
int is_scheduler_probe_source(struct config_item *item);

struct scheduler_policy;
struct scheduler_policy *scheduler_policy_new(const char *name);
void scheduler_policy_drop(struct scheduler_policy *policy);

static inline int nr_def_groups(struct config_group *def_groups[])
{
	int n = 0;
	if (def_groups)
		while (def_groups[n])
			n++;
	return n;
}

/* Subsystems initializers / cleaners */

int krg_sched_info_start(void);
void krg_sched_info_exit(void);

int global_lock_start(void);
void global_lock_exit(void);

int string_list_start(void);
void string_list_exit(void);

int global_config_start(void);
void global_config_exit(void);
int global_config_add(struct hotplug_context *ctx);
int global_config_post_add(struct hotplug_context *ctx);

int remote_pipe_start(void);
void remote_pipe_exit(void);

struct config_group *scheduler_probe_start(void);
void scheduler_probe_exit(void);

struct config_group *scheduler_start(void);
void scheduler_exit(void);

#endif /* __SCHEDULER_INTERNAL_H__ */
