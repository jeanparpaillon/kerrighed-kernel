/*
 *  kerrighed/scheduler/filters/diff_filter.c
 *
 *  Copyright (C) 2008 Louis Rilling - Kerlabs
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <kerrighed/scheduler/filter.h>
#include <kerrighed/scheduler/port.h>

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Louis Rilling <Louis.Rilling@kerlabs.com>");
MODULE_DESCRIPTION("Filter to substract a (variable) value");

struct config_group;

struct diff_filter {
	struct scheduler_filter filter;
	struct scheduler_port second_value_port;
	struct config_group *default_groups[2];
	int second_get_remote_in_progress;
	unsigned long first_value;
};

static inline
struct diff_filter *to_diff_filter(struct scheduler_filter *filter)
{
	return container_of(filter, struct diff_filter, filter);
}

DEFINE_SCHEDULER_PORT_UPDATE_VALUE(second_value_port, port)
{
	struct diff_filter *f;

	f = container_of(port, struct diff_filter, second_value_port);
	scheduler_filter_simple_update_value(&f->filter);
}

static BEGIN_SCHEDULER_PORT_TYPE(second_value_port),
	.SCHEDULER_PORT_UPDATE_VALUE(second_value_port),
	.SCHEDULER_PORT_VALUE_TYPE(second_value_port, unsigned long),
END_SCHEDULER_PORT_TYPE(second_value_port);

static int diff_filter_value(struct diff_filter *df, unsigned long *value_p)
{
	unsigned long first_value, second_value;
	int err;

	err = scheduler_filter_simple_get_value(&df->filter, &first_value, 1);
	if (err < 1)
		goto err;
	err = scheduler_port_get_value(&df->second_value_port,
				       &second_value, 1,
				       NULL, 0);
	if (err < 1)
		goto err;

	*value_p = first_value - second_value;
	return 1;

err:
	return err;
}

DEFINE_SCHEDULER_FILTER_GET_VALUE(diff_filter, filter,
				  unsigned long, value_p, nr)
{
	return diff_filter_value(to_diff_filter(filter), value_p);
}

DEFINE_SCHEDULER_FILTER_SHOW_VALUE(diff_filter, filter, page)
{
	unsigned long diff;
	int ret = diff_filter_value(to_diff_filter(filter), &diff);
	if (ret >= 1)
		ret = sprintf(page, "%lu", diff);
	return ret;
}

DEFINE_SCHEDULER_FILTER_GET_REMOTE_VALUE(diff_filter, filter,
					 node,
					 unsigned long, value_p, nr,
					 unsigned long, in_value_p, in_nr)
{
	struct diff_filter *f = to_diff_filter(filter);
	int ret = -EINVAL;

	if (nr != 1)
		goto out;

	if (f->second_get_remote_in_progress)
		goto second_get;
	ret = scheduler_filter_simple_get_remote_value(filter,
						       node,
						       &f->first_value, 1,
						       in_value_p, in_nr);
	if (ret <= 0)
		goto out;
second_get:
	ret = scheduler_port_get_remote_value(&f->second_value_port,
					      node,
					      value_p, 1,
					      in_value_p, in_nr);
	f->second_get_remote_in_progress = (ret == -EAGAIN);
	if (ret <= 0)
		goto out;

	*value_p = f->first_value - *value_p;
out:
	return ret;
}

/* Forward declaration */
static struct scheduler_filter_type diff_filter_type;

DEFINE_SCHEDULER_FILTER_NEW(diff_filter, name)
{
	struct diff_filter *f = kmalloc(sizeof(*f), GFP_KERNEL);
	int err;

	if (!f)
		goto err_diff;
	err = scheduler_port_init(&f->second_value_port, "second_value",
				  &second_value_port_type, NULL, NULL);
	if (err)
		goto err_second_value;
	f->default_groups[0] =
		scheduler_port_config_group(&f->second_value_port);
	f->default_groups[1] = NULL;
	err = scheduler_filter_init(&f->filter, name, &diff_filter_type,
				    f->default_groups);
	if (err)
		goto err_filter;
	f->second_get_remote_in_progress = 0;

	return &f->filter;

err_filter:
	scheduler_port_cleanup(&f->second_value_port);
err_second_value:
	kfree(f);
err_diff:
	return NULL;
}

DEFINE_SCHEDULER_FILTER_DESTROY(diff_filter, filter)
{
	struct diff_filter *f = to_diff_filter(filter);

	scheduler_filter_cleanup(&f->filter);
	scheduler_port_cleanup(&f->second_value_port);
	kfree(f);
}

static BEGIN_SCHEDULER_FILTER_TYPE(diff_filter),
	.SCHEDULER_FILTER_SOURCE_VALUE_TYPE(diff_filter, unsigned long),
	.SCHEDULER_FILTER_PORT_VALUE_TYPE(diff_filter, unsigned long),
	.SCHEDULER_FILTER_GET_VALUE(diff_filter),
	.SCHEDULER_FILTER_SHOW_VALUE(diff_filter),
	.SCHEDULER_FILTER_GET_REMOTE_VALUE(diff_filter),
END_SCHEDULER_FILTER_TYPE(diff_filter);

int diff_start(void)
{
	int err;

	err = scheduler_port_type_init(&second_value_port_type, NULL);
	if (err)
		goto err_second_value;
	err = scheduler_filter_type_register(&diff_filter_type);
	if (err)
		goto err_register;
out:
	return err;

err_register:
	scheduler_port_type_cleanup(&second_value_port_type);
err_second_value:
	goto out;
}

void diff_exit(void)
{
	scheduler_filter_type_unregister(&diff_filter_type);
	scheduler_port_type_cleanup(&second_value_port_type);
}

module_init(diff_start);
module_exit(diff_exit);
