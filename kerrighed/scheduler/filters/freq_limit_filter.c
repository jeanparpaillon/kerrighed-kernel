/*
 *  kerrighed/scheduler/filters/freq_limit_filter.c
 *
 *  Copyright (C) 2007-2008 Louis Rilling - Kerlabs
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/ktime.h>
#include <kerrighed/scheduler/filter.h>
#include <kerrighed/scheduler/port.h>

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Louis Rilling <Louis.Rilling@kerlabs.com>");
MODULE_DESCRIPTION("Filter to limit the frequency of events");

struct config_group;

struct freq_limit_filter {
	struct scheduler_filter filter;
	u64 min_interval_nsec;
	struct scheduler_port last_event_port;
	struct scheduler_port events_on_going_port;
	struct config_group *default_groups[3];
};

static inline
struct freq_limit_filter *to_freq_limit_filter(struct scheduler_filter *filter)
{
	return container_of(filter, struct freq_limit_filter, filter);
}

DEFINE_SCHEDULER_FILTER_ATTRIBUTE_SHOW(min_interval, filter, attr, page)
{
	struct freq_limit_filter *f = to_freq_limit_filter(filter);
	u64 min_interval_nsec;

	/*
	 * Access to 64 bits is not atomic on 32 bits x86 so locking is
	 * required.
	 */
	scheduler_filter_lock(filter);
	min_interval_nsec = f->min_interval_nsec;
	scheduler_filter_unlock(filter);
	return sprintf(page, "%llu\n", min_interval_nsec);
}

DEFINE_SCHEDULER_FILTER_ATTRIBUTE_STORE(min_interval, filter, attr, buffer, size)
{
	struct freq_limit_filter *f = to_freq_limit_filter(filter);
	char *pos;
	u64 min_interval;

	min_interval = simple_strtoull(buffer, &pos, 10);
	if (((*pos == '\n' && pos - buffer == size - 1)
	     || (*pos == '\0' && pos - buffer == size))
	    && pos != buffer) {
		scheduler_filter_lock(filter);
		f->min_interval_nsec = min_interval;
		scheduler_filter_unlock(filter);
		return size;
	}
	return -EINVAL;
}

static BEGIN_SCHEDULER_FILTER_ATTRIBUTE(min_interval_attr, min_interval, 0664),
	.SCHEDULER_FILTER_ATTRIBUTE_SHOW(min_interval),
	.SCHEDULER_FILTER_ATTRIBUTE_STORE(min_interval),
END_SCHEDULER_FILTER_ATTRIBUTE(min_interval);

static struct scheduler_filter_attribute *freq_limit_attrs[] = {
	&min_interval_attr,
	NULL
};

static BEGIN_SCHEDULER_PORT_TYPE(last_event_port),
	.SCHEDULER_PORT_VALUE_TYPE(last_event_port, ktime_t),
END_SCHEDULER_PORT_TYPE(last_event_port);
static BEGIN_SCHEDULER_PORT_TYPE(events_on_going_port),
	.SCHEDULER_PORT_VALUE_TYPE(events_on_going_port, int),
END_SCHEDULER_PORT_TYPE(events_on_going_port);

DEFINE_SCHEDULER_FILTER_UPDATE_VALUE(freq_limit_filter, filter)
{
	struct freq_limit_filter *f = to_freq_limit_filter(filter);
	ktime_t last_event;
	int on_going;
	ktime_t now;
	struct timespec now_ts;
	u64 interval;
	u64 min_interval;
	int ret;

	scheduler_filter_lock(filter);
	min_interval = f->min_interval_nsec;
	scheduler_filter_unlock(filter);

	if (!min_interval)
		goto propagate;

	ret = scheduler_port_get_value(&f->last_event_port,
				       &last_event, 1, NULL, 0);
	if (ret < 1)
		return;

	ktime_get_ts(&now_ts);
	now = timespec_to_ktime(now_ts);

	interval = (u64) ktime_to_ns(ktime_sub(now, last_event));
	if (interval < min_interval)
		return;

	ret = scheduler_port_get_value(&f->events_on_going_port,
				       &on_going, 1, NULL, 0);
	if (ret == 1 && on_going)
		return;

propagate:
	scheduler_filter_simple_update_value(filter);
}

/* Forward declaration */
static struct scheduler_filter_type freq_limit_filter_type;

DEFINE_SCHEDULER_FILTER_NEW(freq_limit_filter, name)
{
	struct freq_limit_filter *f = kmalloc(sizeof(*f), GFP_KERNEL);
	int err;

	if (!f)
		goto err_freq_limit;
	f->min_interval_nsec = 0;
	err = scheduler_port_init(&f->last_event_port, "last_event",
				  &last_event_port_type, NULL, NULL);
	if (err)
		goto err_last_event;
	err = scheduler_port_init(&f->events_on_going_port, "events_on_going",
				  &events_on_going_port_type, NULL, NULL);
	if (err)
		goto err_events_on_going;
	f->default_groups[0] = scheduler_port_config_group(&f->last_event_port);
	f->default_groups[1] =
		scheduler_port_config_group(&f->events_on_going_port);
	f->default_groups[2] = NULL;
	err = scheduler_filter_init(&f->filter, name, &freq_limit_filter_type,
				    f->default_groups);
	if (err)
		goto err_filter;

	return &f->filter;

err_filter:
	scheduler_port_cleanup(&f->events_on_going_port);
err_events_on_going:
	scheduler_port_cleanup(&f->last_event_port);
err_last_event:
	kfree(f);
err_freq_limit:
	return NULL;
}

DEFINE_SCHEDULER_FILTER_DESTROY(freq_limit_filter, filter)
{
	struct freq_limit_filter *f = to_freq_limit_filter(filter);

	scheduler_filter_cleanup(&f->filter);
	scheduler_port_cleanup(&f->events_on_going_port);
	scheduler_port_cleanup(&f->last_event_port);
	kfree(f);
}

static BEGIN_SCHEDULER_FILTER_TYPE(freq_limit_filter),
	.SCHEDULER_FILTER_UPDATE_VALUE(freq_limit_filter),
	.SCHEDULER_FILTER_SOURCE_VALUE_TYPE(freq_limit_filter, unsigned long),
	.SCHEDULER_FILTER_PORT_VALUE_TYPE(freq_limit_filter, unsigned long),
	.SCHEDULER_FILTER_ATTRIBUTES(freq_limit_filter, freq_limit_attrs),
END_SCHEDULER_FILTER_TYPE(freq_limit_filter);

int freq_limit_start(void)
{
	int err;

	err = scheduler_port_type_init(&last_event_port_type, NULL);
	if (err)
		goto err_last_event;
	err = scheduler_port_type_init(&events_on_going_port_type, NULL);
	if (err)
		goto err_events_on_going;
	err = scheduler_filter_type_register(&freq_limit_filter_type);
	if (err)
		goto err_register;
out:
	return err;

err_register:
	scheduler_port_type_cleanup(&events_on_going_port_type);
err_events_on_going:
	scheduler_port_type_cleanup(&last_event_port_type);
err_last_event:
	goto out;
}

void freq_limit_exit(void)
{
	scheduler_filter_type_unregister(&freq_limit_filter_type);
	scheduler_port_type_cleanup(&events_on_going_port_type);
	scheduler_port_type_cleanup(&last_event_port_type);
}

module_init(freq_limit_start);
module_exit(freq_limit_exit);
