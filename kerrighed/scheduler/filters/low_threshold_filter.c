/*
 *  kerrighed/scheduler/filters/low_threshold_filter.c
 *
 *  Copyright (C) 2007-2008 Louis Rilling - Kerlabs
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <kerrighed/scheduler/filter.h>

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Louis Rilling <Louis.Rilling@kerlabs.com>");
MODULE_DESCRIPTION("Filter to propagate updates of values below a threshold");

struct low_threshold_filter {
	struct scheduler_filter filter;
	unsigned long threshold __attribute__((aligned(sizeof(unsigned long))));
};

/*
 * The threshold attribute is not protected by scheduler_filter_lock() since
 * atomic memory access is sufficient.
 */

static inline
struct low_threshold_filter *
to_low_threshold_filter(struct scheduler_filter *filter)
{
	return container_of(filter, struct low_threshold_filter, filter);
}

DEFINE_SCHEDULER_FILTER_ATTRIBUTE_SHOW(threshold, filter, attr, page)
{
	struct low_threshold_filter *f = to_low_threshold_filter(filter);
	return sprintf(page, "%lu", f->threshold);
}

DEFINE_SCHEDULER_FILTER_ATTRIBUTE_STORE(threshold, filter, attr, page, count)
{
	struct low_threshold_filter *f = to_low_threshold_filter(filter);
	unsigned long new_value;
	char *last_read;

	new_value = simple_strtoul(page, &last_read, 0);
	if (last_read - page + 1 < count
	    || (last_read[1] != '\0' && last_read[1] != '\n'))
		return -EINVAL;
	f->threshold = new_value;
	return count;
}

static BEGIN_SCHEDULER_FILTER_ATTRIBUTE(threshold_attr, threshold, 0666),
	.SCHEDULER_FILTER_ATTRIBUTE_SHOW(threshold),
	.SCHEDULER_FILTER_ATTRIBUTE_STORE(threshold),
END_SCHEDULER_FILTER_ATTRIBUTE(threshold);

static struct scheduler_filter_attribute *low_threshold_attrs[] = {
	&threshold_attr,
	NULL
};

DEFINE_SCHEDULER_FILTER_UPDATE_VALUE(low_threshold_filter, filter)
{
	struct low_threshold_filter *f = to_low_threshold_filter(filter);
	unsigned long value;
	ssize_t ret;

	ret = scheduler_filter_simple_get_value(filter, &value, 1);
	if (ret > 0 && value <= f->threshold)
		scheduler_filter_simple_update_value(filter);
}

/* Forward declaration */
static struct scheduler_filter_type low_threshold_filter_type;

DEFINE_SCHEDULER_FILTER_NEW(low_threshold_filter, name)
{
	struct low_threshold_filter *f = kmalloc(sizeof(*f), GFP_KERNEL);
	int err;

	if (!f)
		goto err_f;
	err = scheduler_filter_init(&f->filter,
				    name,
				    &low_threshold_filter_type,
				    NULL);
	if (err)
		goto err_filter;
	f->threshold = ULONG_MAX;

	return &f->filter;

err_filter:
	kfree(f);
err_f:
	return NULL;
}

DEFINE_SCHEDULER_FILTER_DESTROY(low_threshold_filter, filter)
{
	struct low_threshold_filter *f = to_low_threshold_filter(filter);
	scheduler_filter_cleanup(filter);
	kfree(f);
}

static BEGIN_SCHEDULER_FILTER_TYPE(low_threshold_filter),
	.SCHEDULER_FILTER_UPDATE_VALUE(low_threshold_filter),
	.SCHEDULER_FILTER_SOURCE_VALUE_TYPE(low_threshold_filter,
					    unsigned long),
	.SCHEDULER_FILTER_PORT_VALUE_TYPE(low_threshold_filter, unsigned long),
	.SCHEDULER_FILTER_ATTRIBUTES(low_threshold_filter, low_threshold_attrs),
END_SCHEDULER_FILTER_TYPE(low_threshold_filter);

static int low_threshold_start(void)
{
	return scheduler_filter_type_register(&low_threshold_filter_type);
}

static void low_threshold_exit(void)
{
	scheduler_filter_type_unregister(&low_threshold_filter_type);
}

module_init(low_threshold_start);
module_exit(low_threshold_exit);
