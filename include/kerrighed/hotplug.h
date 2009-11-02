#ifndef __HOTPLUG__
#define __HOTPLUG__

#include <kerrighed/krgnodemask.h>

enum {
	HOTPLUG_PRIO_MEMBERSHIP_ONLINE, // should be done after distributed services management
	HOTPLUG_PRIO_EPM,
	HOTPLUG_PRIO_PROCFS,
	HOTPLUG_PRIO_KDDM,
	HOTPLUG_PRIO_BARRIER,
	HOTPLUG_PRIO_RPC,
	HOTPLUG_PRIO_MEMBERSHIP_PRESENT,
	HOTPLUG_PRIO_MAX // must be the last one
};

typedef enum {
	HOTPLUG_NOTIFY_ADD,
	HOTPLUG_NOTIFY_REMOVE,
	HOTPLUG_NOTIFY_REMOVE_LOCAL, // node side: local operations
	HOTPLUG_NOTIFY_REMOVE_ADVERT, // cluster side
	HOTPLUG_NOTIFY_REMOVE_DISTANT, // node side: remote operations
	HOTPLUG_NOTIFY_REMOVE_ACK, // cluster side
	HOTPLUG_NOTIFY_FAIL,
} hotplug_event_t;

struct hotplug_node_set {
	int subclusterid;
	krgnodemask_t v;
};

struct notifier_block;

int register_hotplug_notifier(int (*notifier_call)(struct notifier_block *, hotplug_event_t, void *),
			      int priority);

struct hotplug_node_set;
int hotplug_add_notify(struct hotplug_node_set *nodes_set,
		       hotplug_event_t event);
int hotplug_remove_notify(struct hotplug_node_set *nodes_set,
			  hotplug_event_t event);
int hotplug_failure_notify(struct hotplug_node_set *nodes_set,
			   hotplug_event_t event);

void hook_register(void *hk, void *f);

struct universe_elem {
	int state;
	int subid;
};
extern struct universe_elem universe[KERRIGHED_MAX_NODES];

extern void (*kh_cluster_autostart)(void);
extern void (*kh_node_reachable)(kerrighed_node_t nodeid);
extern void (*kh_node_unreachable)(kerrighed_node_t nodeid);

void krg_node_arrival(kerrighed_node_t nodeid);
void krg_node_departure(kerrighed_node_t nodeid);

#endif
