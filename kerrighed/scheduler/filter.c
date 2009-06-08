/*
 *  kerrighed/scheduler/filter.c
 *
 *  Copyright (C) 2007 Marko Novak - Xlab
 *  Copyright (C) 2007-2008 Louis Rilling - Kerlabs
 */

#include <linux/kernel.h>
#include <linux/types.h>
#include <kerrighed/sys/types.h>
#include <kerrighed/scheduler/pipe.h>
#include <kerrighed/scheduler/port.h>
#include <kerrighed/scheduler/filter.h>

static int scheduler_filter_attribute_array_length(
	struct scheduler_filter_attribute **attrs)
{
	int nr = 0;
	if (attrs)
		while (attrs[nr])
			nr++;
	return nr;
}

int scheduler_filter_type_register(struct scheduler_filter_type *type)
{
	struct configfs_attribute **tmp_attrs = NULL;
	int nr_attrs, i;
	int err;

	if (!type->source_type.get_value
	    || !type->port_type.new || !type->port_type.destroy)
		return -EINVAL;

	nr_attrs = scheduler_filter_attribute_array_length(type->attrs);
	if (nr_attrs) {
		err = -ENOMEM;
		tmp_attrs = kmalloc(sizeof(*tmp_attrs) * (nr_attrs + 1),
				    GFP_KERNEL);
		if (!tmp_attrs)
			goto err_attrs;
		for (i = 0; i < nr_attrs; i++)
			tmp_attrs[i] = &type->attrs[i]->port_attr.config;
		tmp_attrs[nr_attrs] = NULL;
	}
	err = scheduler_port_type_register(&type->port_type, tmp_attrs);
	kfree(tmp_attrs);

out:
	return err;
err_attrs:
	goto out;
}
EXPORT_SYMBOL(scheduler_filter_type_register);

void scheduler_filter_type_unregister(struct scheduler_filter_type *type)
{
	scheduler_port_type_unregister(&type->port_type);
}
EXPORT_SYMBOL(scheduler_filter_type_unregister);

int scheduler_filter_init(struct scheduler_filter *filter,
			  const char *name,
			  struct scheduler_filter_type *type,
			  struct config_group **default_groups)
{
	scheduler_source_init(&filter->source, &type->source_type);
	return scheduler_port_init(&filter->port, name, &type->port_type,
				   &filter->source,
				   default_groups);
}
EXPORT_SYMBOL(scheduler_filter_init);

void scheduler_filter_cleanup(struct scheduler_filter *filter)
{
	scheduler_port_cleanup(&filter->port);
	scheduler_source_cleanup(&filter->source);
}
EXPORT_SYMBOL(scheduler_filter_cleanup);

int scheduler_filter_simple_source_get_value(struct scheduler_source *source,
					     void *value_p, unsigned int nr,
					     const void *in_value_p,
					     unsigned int in_nr)
{
	struct scheduler_filter *filter;
	filter = container_of(source, struct scheduler_filter, source);
	return scheduler_port_get_value(&filter->port,
					value_p, nr, in_value_p, in_nr);
}
EXPORT_SYMBOL(scheduler_filter_simple_source_get_value);

ssize_t
scheduler_filter_simple_source_show_value(struct scheduler_source *source,
					  char *page)
{
	struct scheduler_filter *filter;
	filter = container_of(source, struct scheduler_filter, source);
	return scheduler_port_show_value(&filter->port, page);
}
EXPORT_SYMBOL(scheduler_filter_simple_source_show_value);

void scheduler_filter_simple_sink_update_value(struct scheduler_sink *sink,
					       struct scheduler_source *source)
{
	struct scheduler_filter *filter;
	filter = container_of(sink, struct scheduler_filter, port.sink);
	scheduler_source_publish(&filter->source);
}
EXPORT_SYMBOL(scheduler_filter_simple_sink_update_value);
