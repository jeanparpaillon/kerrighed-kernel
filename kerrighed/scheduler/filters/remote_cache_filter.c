/*
 *  kerrighed/scheduler/filters/remote_cache_filter.c
 *
 *  Copyright (C) 2007-2008 Louis Rilling - Kerlabs
 */

#include <linux/module.h>
#include <linux/workqueue.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <kerrighed/sys/types.h>
#include <kerrighed/krgnodemask.h>
#include <kerrighed/scheduler/filter.h>

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Louis Rilling <Louis.Rilling@kerlabs.com>");
MODULE_DESCRIPTION("Filter to proactively cache remote values");

struct remote_cache_filter {
	struct scheduler_filter filter;
	unsigned long remote_values[KERRIGHED_MAX_NODES];
	krgnodemask_t available_values;
	unsigned long polling_period; /* in jiffies */
	kerrighed_node_t current_node;
	struct delayed_work polling_work;
	int active; /* Is it able to collect values? */
};

static inline
struct remote_cache_filter *
to_remote_cache_filter(struct scheduler_filter *filter)
{
	return container_of(filter, struct remote_cache_filter, filter);
}

static inline void rc_lock(struct remote_cache_filter *rc_filter)
{
	scheduler_filter_lock(&rc_filter->filter);
}

static inline void rc_unlock(struct remote_cache_filter *rc_filter)
{
	scheduler_filter_unlock(&rc_filter->filter);
}

static void schedule_next_poll(struct remote_cache_filter *rc_filter)
{
	unsigned long delay;

	delay = rc_filter->polling_period;
	if (rc_filter->current_node != KERRIGHED_NODE_ID_NONE)
		/*
		 * Last polling phase could not finish within period. Schedule
		 * next phase ASAP
		 */
		delay = 1;
	else if (!delay)
		/*
		 * We are forced to schedule a poll in order to make
		 * cancel_rearming_delayed_work() do its job.
		 *
		 * Schedule it every hour
		 */
		delay = msecs_to_jiffies(3600000);
	schedule_delayed_work(&rc_filter->polling_work, delay);
}

static void reschedule_next_poll(struct remote_cache_filter *rc_filter)
{
	cancel_delayed_work(&rc_filter->polling_work);
	schedule_next_poll(rc_filter);
}

DEFINE_SCHEDULER_FILTER_ATTRIBUTE_SHOW(polling_period, filter, attr, page)
{
	struct remote_cache_filter *f = to_remote_cache_filter(filter);
	unsigned long period;

	rc_lock(f);
	period = f->polling_period;
	rc_unlock(f);
	return sprintf(page, "%u", jiffies_to_msecs(period));
}

DEFINE_SCHEDULER_FILTER_ATTRIBUTE_STORE(polling_period, filter, attr, page, count)
{
	struct remote_cache_filter *f = to_remote_cache_filter(filter);
	unsigned long new_period;
	char *last_read;

	new_period = simple_strtoul(page, &last_read, 0);
	if (last_read - page + 1 < count
	    || (last_read[1] != '\0' && last_read[1] != '\n'))
		return -EINVAL;
	new_period = msecs_to_jiffies(new_period);
	rc_lock(f);
	f->polling_period = new_period;
	reschedule_next_poll(f);
	rc_unlock(f);

	return count;
}

static BEGIN_SCHEDULER_FILTER_ATTRIBUTE(polling_period_attr, polling_period, 0666),
	.SCHEDULER_FILTER_ATTRIBUTE_SHOW(polling_period),
	.SCHEDULER_FILTER_ATTRIBUTE_STORE(polling_period),
END_SCHEDULER_FILTER_ATTRIBUTE(polling_period);

static struct scheduler_filter_attribute *remote_cache_attrs[] = {
	&polling_period_attr,
	NULL
};

/*
 * Gets called:
 * - from the scheduler framework, but only if it holds a reference,
 * - or from the polling worker.
 * So, when the destroy method is called, can only be called from the polling
 * worker.
 */
static int try_get_remote_values(struct remote_cache_filter *f)
{
	kerrighed_node_t current_node = f->current_node;
	int nr = 0;
	int ret = 0;

	while (current_node != KERRIGHED_NODE_ID_NONE) {
		ret = scheduler_filter_simple_get_remote_value(
			&f->filter,
			current_node,
			&f->remote_values[current_node], 1,
			NULL, 0);
		if (ret == -EAGAIN)
			break;
		nr++;
		if (ret > 0)
			krgnode_set(current_node, f->available_values);
		else
			krgnode_clear(current_node, f->available_values);
		current_node = krgnode_next_online(current_node);
		if (current_node == KERRIGHED_MAX_NODES)
			current_node = KERRIGHED_NODE_ID_NONE;
	}
	f->current_node = current_node;

	if (ret == -EACCES)
		f->active = 0;

	return nr;
}

static void get_remote_values(struct remote_cache_filter *rc_filter)
{
	kerrighed_node_t first_node;

	if (rc_filter->current_node == KERRIGHED_NODE_ID_NONE) {
		first_node = nth_online_krgnode(0);
		if (first_node != KERRIGHED_MAX_NODES) {
			rc_filter->current_node = first_node;
			try_get_remote_values(rc_filter);
		}
	}
}

static void polling_worker(struct work_struct *work)
{
	struct remote_cache_filter *f =
		container_of(work,
			     struct remote_cache_filter, polling_work.work);

	rc_lock(f);
	schedule_next_poll(f);
	get_remote_values(f);
	rc_unlock(f);
}

DEFINE_SCHEDULER_FILTER_UPDATE_VALUE(remote_cache_filter, filter)
{
	struct remote_cache_filter *f = to_remote_cache_filter(filter);
	int nr;

	rc_lock(f);
	nr = try_get_remote_values(f);
	rc_unlock(f);

	/*
	 * Propagate updates from the connected local source.
	 *
	 * We may miss some if incidentally a remote value becomes available at
	 * the same time. Let's hope this is not to bad...
	 */
	if (!nr)
		/* Update comes from the connected local source */
		scheduler_filter_simple_update_value(filter);
}

DEFINE_SCHEDULER_FILTER_GET_REMOTE_VALUE(remote_cache_filter, filter,
					 node,
					 unsigned long, value_p, nr,
					 unsigned int, param_p, nr_param)
{
	struct remote_cache_filter *f = to_remote_cache_filter(filter);
	int ret = 0;

	rc_lock(f);
	if (!f->active) {
		/*
		 * Do not wait for the next worker activation to begin reading
		 * remote values
		 */
		f->active = 1;
		reschedule_next_poll(f);
		get_remote_values(f);
	}
	if (krgnode_isset(node, f->available_values)) {
		value_p[0] = f->remote_values[node];
		ret = 1;
	}
	rc_unlock(f);

	return ret;
}

/* Forward declaration */
static struct scheduler_filter_type remote_cache_filter_type;

DEFINE_SCHEDULER_FILTER_NEW(remote_cache_filter, name)
{
	struct remote_cache_filter *f = kmalloc(sizeof(*f), GFP_KERNEL);
	int err;

	if (!f)
		goto err_f;
	err = scheduler_filter_init(&f->filter, name, &remote_cache_filter_type,
				    NULL);
	if (err)
		goto err_filter;
	krgnodes_clear(f->available_values);
	f->polling_period = 0;
	f->current_node = KERRIGHED_NODE_ID_NONE;
	INIT_DELAYED_WORK(&f->polling_work, polling_worker);
	f->active = 0;
	schedule_next_poll(f);

	return &f->filter;

err_filter:
	kfree(f);
err_f:
	return NULL;
}

DEFINE_SCHEDULER_FILTER_DESTROY(remote_cache_filter, filter)
{
	struct remote_cache_filter *f = to_remote_cache_filter(filter);
	cancel_rearming_delayed_work(&f->polling_work);
	scheduler_filter_cleanup(filter);
	kfree(f);
}

static BEGIN_SCHEDULER_FILTER_TYPE(remote_cache_filter),
	.SCHEDULER_FILTER_UPDATE_VALUE(remote_cache_filter),
	.SCHEDULER_FILTER_GET_REMOTE_VALUE(remote_cache_filter),
	.SCHEDULER_FILTER_SOURCE_VALUE_TYPE(remote_cache_filter, unsigned long),
	.SCHEDULER_FILTER_PORT_VALUE_TYPE(remote_cache_filter, unsigned long),
	.SCHEDULER_FILTER_ATTRIBUTES(remote_cache_filter, remote_cache_attrs),
END_SCHEDULER_FILTER_TYPE(remote_cache_filter);

static int remote_cache_start(void)
{
	return scheduler_filter_type_register(&remote_cache_filter_type);
}

static void remote_cache_exit(void)
{
	scheduler_filter_type_unregister(&remote_cache_filter_type);
}

module_init(remote_cache_start);
module_exit(remote_cache_exit);
