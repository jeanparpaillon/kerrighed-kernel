#ifndef __HOTPLUG_INTERNAL__
#define __HOTPLUG_INTERNAL__

enum {
	CLUSTER_UNDEF,
	CLUSTER_DEF,
};

extern char clusters_status[KERRIGHED_MAX_CLUSTERS];

extern struct kobject *krghotplugsys;

extern struct workqueue_struct *krg_ha_wq;

extern struct work_struct fail_work;

extern struct mutex hotplug_mutex;

int hooks_start(void);
void hooks_stop(void);

struct hotplug_context;

int hotplug_queue_request(struct hotplug_context *ctx);
int hotplug_start_request(struct hotplug_context *ctx);
void hotplug_finish_request(struct hotplug_context *ctx);

int do_cluster_start(struct hotplug_context *ctx);
int __nodes_add(struct hotplug_context *ctx);
void local_add_done(struct rpc_desc *desc);
void self_remove(struct krg_namespace *ns);

int repair_monitor(void);
void update_heartbeat(void);

int krgnodemask_copy_from_user(krgnodemask_t *dst, __krgnodemask_t *from);

int krg_set_cluster_creator(void __user *arg);

int heartbeat_init(void);
int hotplug_add_init(void);
int hotplug_remove_init(void);
int hotplug_failure_init(void);
int hotplug_hooks_init(void);
int hotplug_cluster_init(void);
int hotplug_namespace_init(void);

int hotplug_membership_init(void);
void hotplug_membership_cleanup(void);

#endif
