/*
 *  Copyright (C) 2006-2007, Pascal Gallard, Kerlabs.
 */

#include <linux/mutex.h>
#include <linux/notifier.h>
#include <linux/slab.h>

#include <kerrighed/hotplug.h>
#include <kerrighed/krgnodemask.h>

static RAW_NOTIFIER_HEAD(hotplug_chain_add);
static RAW_NOTIFIER_HEAD(hotplug_chain_remove);

static DEFINE_MUTEX(hotplug_mutex);

int register_hotplug_notifier(int (*notifier_call)(struct notifier_block *, hotplug_event_t, void *),
			      int priority)
{
	int err;
	struct notifier_block *nb;

	/* Insert into the addition chain */
	nb = kmalloc(sizeof(*nb), GFP_KERNEL);
	if (!nb)
		return -ENOMEM;
	nb->notifier_call = (int (*)(struct notifier_block *, unsigned long, void *))(notifier_call);
	nb->priority = priority;

	mutex_lock(&hotplug_mutex);
	err = raw_notifier_chain_register(&hotplug_chain_add, nb);
	mutex_unlock(&hotplug_mutex);

	if (err)
		return err;
	
	/* Insert into the removal chain */
	nb = kmalloc(sizeof(*nb), GFP_KERNEL);
	if (!nb)
		return -ENOMEM;
	nb->notifier_call =  (int (*)(struct notifier_block *, unsigned long, void *))(notifier_call);
	nb->priority = HOTPLUG_PRIO_MAX-priority;
	
	mutex_lock(&hotplug_mutex);
	err = raw_notifier_chain_register(&hotplug_chain_remove, nb);
	mutex_unlock(&hotplug_mutex);

	return err;
}

int hotplug_add_notify(struct hotplug_context *ctx, hotplug_event_t event)
{
	return raw_notifier_call_chain(&hotplug_chain_add, event, ctx);
}

int hotplug_remove_notify(struct hotplug_context *ctx, hotplug_event_t event)
{
	return raw_notifier_call_chain(&hotplug_chain_remove, event, ctx);
}

int hotplug_failure_notify(struct hotplug_node_set *nodes_set,
			   hotplug_event_t event)
{
	return 0;
}
