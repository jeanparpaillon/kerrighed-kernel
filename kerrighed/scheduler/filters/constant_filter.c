/*
 *  kerrighed/scheduler/filters/constant_filter.c
 *
 *  Copyright (C) 2007-2008 Louis Rilling - Kerlabs
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <kerrighed/scheduler/filter.h>

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Louis Rilling <Louis.Rilling@kerlabs.com>");
MODULE_DESCRIPTION("Filter providing a constant value");

struct constant_filter {
	struct scheduler_filter filter;
	unsigned long constant __attribute__((aligned(sizeof(unsigned long))));
};

/*
 * The constant attribute is not protected by scheduler_filter_lock() since
 * atomic memory access is sufficient.
 */

static inline
struct constant_filter *to_constant_filter(struct scheduler_filter *filter)
{
	return container_of(filter, struct constant_filter, filter);
}

DEFINE_SCHEDULER_FILTER_ATTRIBUTE_SHOW(constant, filter, attr, page)
{
	struct constant_filter *f = to_constant_filter(filter);
	return sprintf(page, "%lu", f->constant);
}

DEFINE_SCHEDULER_FILTER_ATTRIBUTE_STORE(constant, filter, attr, page, count)
{
	struct constant_filter *f = to_constant_filter(filter);
	unsigned long new_value;
	char *last_read;

	new_value = simple_strtoul(page, &last_read, 0);
	if (last_read - page + 1 < count
	    || (last_read[1] != '\0' && last_read[1] != '\n'))
		return -EINVAL;
	f->constant = new_value;
	return count;
}

static BEGIN_SCHEDULER_FILTER_ATTRIBUTE(constant_attr, constant, 0666),
	.SCHEDULER_FILTER_ATTRIBUTE_SHOW(constant),
	.SCHEDULER_FILTER_ATTRIBUTE_STORE(constant),
END_SCHEDULER_FILTER_ATTRIBUTE(constant);

static struct scheduler_filter_attribute *constant_attrs[] = {
	&constant_attr,
	NULL
};

DEFINE_SCHEDULER_FILTER_GET_VALUE(constant_filter, filter,
				  unsigned long, value_p, nr)
{
	struct constant_filter *f = to_constant_filter(filter);
	int i;

	for (i = 0; i < nr; i++)
		value_p[i] = f->constant;

	return nr;
}

DEFINE_SCHEDULER_FILTER_SHOW_VALUE(constant_filter, filter, page)
{
	struct constant_filter *f = to_constant_filter(filter);
	return sprintf(page, "%lu", f->constant);
}

DEFINE_SCHEDULER_FILTER_GET_REMOTE_VALUE(constant_filter, filter,
					 node,
					 unsigned long, value_p, nr,
					 unsigned long, in_value_p, in_nr)
{
	struct constant_filter *f = to_constant_filter(filter);
	int i;

	for (i = 0; i < nr; i++)
		value_p[i] = f->constant;

	return nr;
}

/* Forward declaration */
static struct scheduler_filter_type constant_filter_type;

DEFINE_SCHEDULER_FILTER_NEW(constant_filter, name)
{
	struct constant_filter *f = kmalloc(sizeof(*f), GFP_KERNEL);
	int err;

	if (!f)
		goto err_f;
	err = scheduler_filter_init(&f->filter,
				    name,
				    &constant_filter_type,
				    NULL);
	if (err)
		goto err_filter;
	f->constant = 0;

	return &f->filter;

 err_filter:
	kfree(f);
 err_f:
	return NULL;
}

DEFINE_SCHEDULER_FILTER_DESTROY(constant_filter, filter)
{
	struct constant_filter *f = to_constant_filter(filter);
	scheduler_filter_cleanup(filter);
	kfree(f);
}

static BEGIN_SCHEDULER_FILTER_TYPE(constant_filter),
	.SCHEDULER_FILTER_SOURCE_VALUE_TYPE(constant_filter,
					    unsigned long),
	/* Not used but mandatory */
	.SCHEDULER_FILTER_PORT_VALUE_TYPE(constant_filter, unsigned long),
	.SCHEDULER_FILTER_GET_VALUE(constant_filter),
	.SCHEDULER_FILTER_SHOW_VALUE(constant_filter),
	.SCHEDULER_FILTER_GET_REMOTE_VALUE(constant_filter),
	.SCHEDULER_FILTER_ATTRIBUTES(constant_filter, constant_attrs),
END_SCHEDULER_FILTER_TYPE(constant_filter);

static int constant_start(void)
{
	return scheduler_filter_type_register(&constant_filter_type);
}

static void constant_exit(void)
{
	scheduler_filter_type_unregister(&constant_filter_type);
}

module_init(constant_start);
module_exit(constant_exit);
