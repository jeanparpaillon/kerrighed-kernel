/*
 *  kerrighed/scheduler/probe.c
 *
 *  Copyright (C) 2007 Marko Novak - Xlab
 *  Copyright (C) 2007-2008 Louis Rilling - Kerlabs
 */

#include <linux/module.h>
#include <linux/nsproxy.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/kmod.h>
#include <linux/workqueue.h>
#include <linux/kernel.h>
#include <linux/jiffies.h>
#include <linux/string.h>
#include <kerrighed/krgflags.h>
#include <kerrighed/scheduler/pipe.h>
#include <kerrighed/scheduler/global_config.h>
#include <kerrighed/scheduler/probe.h>

#include "internal.h"

/**
 * This structure represents pluggable probes for measuring various system
 * characteristics (e.g. CPU usage, memory usage, ...). User can implement these
 * probes as separate Linux kernel modules and inserts them dynamcally into
 * kernel. By doing this, it extends set of resource properties that are being
 * measured.
 * The probe module is loaded by issuing
 * "mkdir /config/krg_scheduler/probes/<probe_name>" command. When probe is
 * loaded it starts measuring its system characteristic. Probes can also be
 * deactivated by issuing "rmdir /config/krg_scheduler/probes/<probe_name>"
 * command from user space.
 *
 * @author Marko Novak, Louis Rilling
 */
struct scheduler_probe {
	struct config_group group; /** representation of probe in ConfigFS. */

	struct list_head list; /** list of registered probes. */

	unsigned long probe_period; /** timeout between subsequent measurements.
				      * Note: here, time is saved in jiffies.*/
	struct delayed_work work; /** work struct for periodically performing
				   * measurements. */

	spinlock_t lock; /** lock for synchronizing probe accesses. */

	struct global_config_item global_item; /** Used by global config
						* subsystem */
};

static
inline
struct scheduler_probe *to_scheduler_probe(struct config_item *item)
{
	return container_of(to_config_group(item),
			    struct scheduler_probe, group);
}

static
inline
struct scheduler_probe_type *
scheduler_probe_type_of(struct scheduler_probe *probe)
{
	return container_of(probe->group.cg_item.ci_type,
			    struct scheduler_probe_type, item_type);
}

static
inline
struct scheduler_probe_attribute *
to_scheduler_probe_attribute(struct configfs_attribute *attr)
{
	return container_of(attr, struct scheduler_probe_attribute, config);
}

static
inline
struct scheduler_probe_source *
to_scheduler_probe_source(struct config_item *item)
{
	return container_of(to_scheduler_pipe(item),
			    struct scheduler_probe_source, pipe);
}

static
inline
struct scheduler_probe_source_type *
scheduler_probe_source_type_of(struct scheduler_probe_source *probe_source)
{
	return container_of(scheduler_pipe_type_of(&(probe_source)->pipe),
			    struct scheduler_probe_source_type, pipe_type);
}

static
inline
struct scheduler_probe_source_attribute *
to_scheduler_probe_source_attribute(struct configfs_attribute *attr)
{
	return container_of(attr,
			    struct scheduler_probe_source_attribute, config);
}

/* a spinlock protecting access to the list of registered probes. */
static DEFINE_SPINLOCK(probes_lock);
/* List of registered probes. */
static LIST_HEAD(probes_list);

void scheduler_probe_lock(struct scheduler_probe *probe)
{
	spin_lock(&probe->lock);
}
EXPORT_SYMBOL(scheduler_probe_lock);

void scheduler_probe_unlock(struct scheduler_probe *probe)
{
	spin_unlock(&probe->lock);
}
EXPORT_SYMBOL(scheduler_probe_unlock);

/**
 * General function for reading probes' ConfigFS attributes.
 * @author Marko Novak, Louis Rilling
 */
static ssize_t scheduler_probe_attribute_show(struct config_item *item,
					      struct configfs_attribute *attr,
					      char *page)
{
	struct scheduler_probe_attribute *probe_attr =
		to_scheduler_probe_attribute(attr);
	struct scheduler_probe *probe = to_scheduler_probe(item);
	ssize_t ret = 0;

	if (probe_attr->show) {
		scheduler_probe_lock(probe);
		ret = probe_attr->show(probe, page);
		scheduler_probe_unlock(probe);
	}

	return ret;
}

/**
 * General function for storing probes' ConfigFS attributes.
 */
static ssize_t scheduler_probe_attribute_store(struct config_item *item,
					       struct configfs_attribute *attr,
					       const char *page, size_t count)
{
	struct scheduler_probe_attribute *probe_attr =
		to_scheduler_probe_attribute(attr);
	struct scheduler_probe *probe = to_scheduler_probe(item);
	struct string_list_object *list;
	ssize_t ret = 0;

	if (!(current->flags & PF_KTHREAD) && !current->nsproxy->krg_ns)
		return -EPERM;

	if (probe_attr->store) {
		list = global_config_attr_store_begin(item);
		if (IS_ERR(list))
			return PTR_ERR(list);

		scheduler_probe_lock(probe);
		ret = probe_attr->store(probe, page, count);
		scheduler_probe_unlock(probe);

		if (ret >= 0)
			ret = global_config_attr_store_end(list,
							   item, attr,
							   page, ret);
		else
			global_config_attr_store_error(list, item);
	}

	return ret;
}

static struct configfs_item_operations scheduler_probe_item_ops = {
	.show_attribute = scheduler_probe_attribute_show,
	.store_attribute = scheduler_probe_attribute_store,
};

/**
 * Function for reading "probe_period" attribute.
 * @author Marko Novak, Louis Rilling
 */
static ssize_t scheduler_probe_attr_period_show(struct scheduler_probe *probe,
						char *page)
{
	ssize_t ret;
	/* print timeout in milliseconds */
	ret = sprintf(page, "%u\n", jiffies_to_msecs(probe->probe_period));
	return ret;
}

/**
 * Function for storing "probe_period" attribute.
 * @author Marko Novak, Louis Rilling
 */
static ssize_t scheduler_probe_attr_period_store(struct scheduler_probe *probe,
						 const char *page, size_t count)
{
	unsigned tmp_period;
	char *last_read;

	tmp_period = simple_strtoul(page, &last_read, 0);
	if (last_read - page + 1 < count
	    || (last_read[1] != '\0' && last_read[1] != '\n'))
		return -EINVAL;

	probe->probe_period = msecs_to_jiffies(tmp_period);

	return count;
}

/**
 * "probe_period" attribute.
 * @author Marko Novak, Louis Rilling
 */
static SCHEDULER_PROBE_ATTRIBUTE(scheduler_probe_attr_period,
				 "probe_period",
				 S_IRUGO | S_IWUSR,
				 scheduler_probe_attr_period_show,
				 scheduler_probe_attr_period_store);

/**
 * Determines length of a NULL-terminated array.
 */
static int probe_source_array_length(struct scheduler_probe_source **sources)
{
	int i;
	if (!sources)
		return 0;
	for (i=0; sources[i] != NULL; i++)
		;
	return i;
}

static inline char *scheduler_probe_name(struct scheduler_probe *probe)
{
	return config_item_name(&probe->group.cg_item);
}

static void refresh_subscribers(struct scheduler_probe *p)
{
	int i;
	struct scheduler_probe_source *tmp_ps;
	struct scheduler_probe_source_type *tmp_pst;

	/* check which measurements have changed since last time. */
	for (i = 0; p->group.default_groups[i] != NULL; i++) {
		tmp_ps = to_scheduler_probe_source(
			&p->group.default_groups[i]->cg_item);
		tmp_pst = scheduler_probe_source_type_of(tmp_ps);
		if (tmp_pst->has_changed && tmp_pst->has_changed()) {
			/*
			 * if value has changed, run update function
			 * of all the subscribers.
			 */
			scheduler_probe_unlock(p);
			scheduler_source_publish(&tmp_ps->source);
			scheduler_probe_lock(p);
		}
	}
}

/**
 * General function for periodically performing probe measurements.
 */
static void probe_refresh_func(struct work_struct *work)
{
	struct scheduler_probe *p = container_of(
		container_of(work, struct delayed_work, work),
		struct scheduler_probe, work);
	struct scheduler_probe_type *type = scheduler_probe_type_of(p);

	scheduler_probe_lock(p);
	if (type->perform_measurement) {
		type->perform_measurement();
		refresh_subscribers(p);
	}
	scheduler_probe_unlock(p);
	/* schedule next measurement. */
	schedule_delayed_work(&p->work, p->probe_period);
}

void scheduler_probe_source_lock(struct scheduler_probe_source *probe_source)
{
	scheduler_probe_lock(probe_source->parent);
}
EXPORT_SYMBOL(scheduler_probe_source_lock);

void scheduler_probe_source_unlock(struct scheduler_probe_source *probe_source)
{
	scheduler_probe_unlock(probe_source->parent);
}
EXPORT_SYMBOL(scheduler_probe_source_unlock);

static void __scheduler_probe_source_notify_update(struct work_struct *work)
{
	struct scheduler_probe_source *s =
		container_of(work,
			     struct scheduler_probe_source, notify_update_work);

	scheduler_source_publish(&s->source);
}

/**
 * Function that a probe source should call when the value changes and the probe
 * does not have a perform_measurement() method.
 * Does nothing if the probe provides a perform_measurement() method.
 *
 * @param source		Source having been updated
 */
void scheduler_probe_source_notify_update(struct scheduler_probe_source *source)
{
	struct scheduler_probe *p = source->parent;

	if (scheduler_probe_type_of(p)->perform_measurement)
		return;

	schedule_work(&source->notify_update_work);
}
EXPORT_SYMBOL(scheduler_probe_source_notify_update);

/**
 * General function for reading probe sources' ConfigFS attributes.
 * @author Marko Novak, Louis Rilling
 */
static
ssize_t scheduler_probe_source_attribute_show(struct config_item *item,
					      struct configfs_attribute *attr,
					      char *page)
{
	struct scheduler_probe_source_attribute *source_attr;
	struct scheduler_probe_source *ps = to_scheduler_probe_source(item);
	ssize_t ret;
	int handled;

	ret = scheduler_pipe_show_attribute(&ps->pipe, attr, page, &handled);
	if (!handled) {
		ret = -EACCES;

		source_attr = to_scheduler_probe_source_attribute(attr);
		if (source_attr->show) {
			scheduler_probe_source_lock(ps);
			ret = source_attr->show(page);
			scheduler_probe_source_unlock(ps);
		}
	}

	return ret;
}

/**
 * General function for storing probe sources' ConfigFS attributes.
 * @author Marko Novak, Louis Rilling
 */
static
ssize_t scheduler_probe_source_attribute_store(struct config_item *item,
					       struct configfs_attribute *attr,
					       const char *page, size_t count)
{
        struct scheduler_probe_source_attribute *source_attr =
		to_scheduler_probe_source_attribute(attr);
        struct scheduler_probe_source *ps = to_scheduler_probe_source(item);
	struct string_list_object *list;
	ssize_t ret;
	int handled;

	if (!(current->flags & PF_KTHREAD) && !current->nsproxy->krg_ns)
		return -EPERM;

	list = global_config_attr_store_begin(item);
	if (IS_ERR(list))
		return PTR_ERR(list);

	ret = scheduler_pipe_store_attribute(&ps->pipe, attr, page, count,
					     &handled);
	if (!handled) {
		ret = -EACCES;
		if (source_attr->store) {
			scheduler_probe_source_lock(ps);
			ret = source_attr->store(page, count);
			scheduler_probe_source_unlock(ps);
		}
	}

	if (ret >= 0)
		ret = global_config_attr_store_end(list,
						   item, attr,
						   page, ret);
	else
		global_config_attr_store_error(list, item);

        return ret;
}

static struct configfs_item_operations scheduler_probe_source_item_ops = {
	.show_attribute = scheduler_probe_source_attribute_show,
	.store_attribute = scheduler_probe_source_attribute_store,
};

static int probe_source_attribute_array_length(
	struct scheduler_probe_source_attribute **attrs)
{
	int nr = 0;
	if (attrs)
		while (attrs[nr])
			nr++;
	return nr;
}

/**
 * This function allocates memory and initializes a probe source.
 * @author Marko Novak, Louis Rilling
 *
 * @param type		Type describing the probe source, defined with
 *			SCHEDULER_PROBE_SOURCE_TYPE
 * @param name		Name of the source's subdirectory in the probe's
 *			directory. Must be unique for a given a probe.
 *
 * @return		Pointer to the created probe_source, or NULL if error
 */
struct scheduler_probe_source *
scheduler_probe_source_create(struct scheduler_probe_source_type *type,
			      const char *name)
{
	struct scheduler_probe_source *tmp_ps = NULL;
	struct module *owner = type->pipe_type.item_type.ct_owner;
	struct configfs_attribute **tmp_attrs;
	int nr_attrs;
	int err;

	/* fixup type */
	type->pipe_type = (struct scheduler_pipe_type)
		SCHEDULER_PIPE_TYPE_INIT(owner,
					 &scheduler_probe_source_item_ops, NULL,
					 &type->source_type, NULL);

	nr_attrs = probe_source_attribute_array_length(type->attrs);
	tmp_attrs = NULL;
	if (nr_attrs) {
		int i;

		tmp_attrs = kmalloc((nr_attrs + 1) * sizeof(*tmp_attrs),
				    GFP_KERNEL);
		if (!tmp_attrs)
			goto err_pipe_type;
		for (i = 0; i < nr_attrs; i++)
			tmp_attrs[i] = &type->attrs[i]->config;
		tmp_attrs[nr_attrs] = NULL;
	}
	err = scheduler_pipe_type_init(&type->pipe_type, tmp_attrs);
	kfree(tmp_attrs);
	if (err)
		goto err_pipe_type;

	tmp_ps = kmalloc(sizeof(*tmp_ps), GFP_KERNEL);
	if (!tmp_ps)
		goto err_source;
	/* initialize scheduler_probe_source. */
	memset(tmp_ps, 0, sizeof(*tmp_ps));

	scheduler_source_init(&tmp_ps->source, &type->source_type);
	if (scheduler_pipe_init(&tmp_ps->pipe, name, &type->pipe_type,
				&tmp_ps->source, NULL, NULL))
		goto err_pipe;
	INIT_WORK(&tmp_ps->notify_update_work,
		  __scheduler_probe_source_notify_update);

	return tmp_ps;

err_pipe:
	kfree(tmp_ps);
err_source:
	scheduler_pipe_type_cleanup(&type->pipe_type);
err_pipe_type:
	return NULL;
}

void scheduler_probe_source_free(struct scheduler_probe_source *source)
{
	struct scheduler_probe_source_type *type =
		scheduler_probe_source_type_of(source);
	scheduler_pipe_cleanup(&source->pipe);
	scheduler_source_cleanup(&source->source);
	kfree(source);
	scheduler_pipe_type_cleanup(&type->pipe_type);
}

/**
 * Checks that item is an source subdir of a probe.
 * @author Louis Rilling, Marko Novak
 *
 * @param item		pointer to the config_item to check
 */
int is_scheduler_probe_source(struct config_item *item)
{
	return item->ci_type
		&& item->ci_type->ct_item_ops ==
			&scheduler_probe_source_item_ops;
}

static void scheduler_probe_drop(struct global_config_item *);

static struct global_config_drop_operations scheduler_probe_drop_ops = {
	.drop_func = scheduler_probe_drop,
	.is_symlink = 0
};

static
int probe_attribute_array_length(struct scheduler_probe_attribute **attrs)
{
	int nr = 0;
	if (attrs)
		while (attrs[nr])
			nr++;
	return nr;
}

/**
 * This function allocates memory for new probe and initializes it.
 * @author Marko Novak, Louis Rilling
 *
 * @param name          name of the probe. This name must be unique for each
 *			probe.
 * @param attrs         array of probe's attributes.
 * @param ops           pointer to probe's operations.
 * @param owner         pointer to module that implements probe.
 *
 * @return              pointer to newly create probe or NULL if probe creation
 *                      failed.
 */
struct scheduler_probe *
scheduler_probe_create(struct scheduler_probe_type *type,
		       const char *name,
		       struct scheduler_probe_source **sources,
		       struct config_group *def_groups[])
{
	int num_sources;
	int nr_attrs;
	int nr_groups;
	int i;
	struct config_group **tmp_def = NULL;
	struct configfs_attribute **tmp_attrs = NULL;
	struct scheduler_probe *tmp_probe = NULL;

	num_sources = probe_source_array_length(sources);
	nr_attrs = probe_attribute_array_length(type->attrs);
	nr_groups = nr_def_groups(def_groups);
	tmp_probe = kmalloc(sizeof(*tmp_probe), GFP_KERNEL);
	/*
	 * allocate 2 more elements in array of pointers: one for
	 * probe_period attribute and one for NULL element which marks
	 * the end of array.
	 */
	tmp_attrs = kmalloc(sizeof(*tmp_attrs) * (nr_attrs + 2), GFP_KERNEL);
	tmp_def = kcalloc(num_sources + nr_groups + 1, sizeof(*tmp_def), GFP_KERNEL);

	if (!tmp_probe || !tmp_attrs || !tmp_def)
		goto out_kmalloc;

	/* initialize attributes */
	for (i = 0; i < nr_attrs; i++)
		tmp_attrs[i] = &type->attrs[i]->config;
	tmp_attrs[nr_attrs] = &scheduler_probe_attr_period.config;
	tmp_attrs[nr_attrs + 1] = NULL;

	/* initialize default groups */
	for (i=0; i<num_sources; i++) {
		tmp_def[i] = &sources[i]->pipe.config;

		/* set current probe as parent of scheduler_probe_source. */
		sources[i]->parent = tmp_probe;
	}

	/* append ports to default groups */
	for (i = 0; i < nr_groups; i++)
		tmp_def[num_sources + i] = def_groups[i];

	tmp_def[num_sources + nr_groups] = NULL;

	/* initialize probe type. */
	type->item_type.ct_item_ops = &scheduler_probe_item_ops;
	type->item_type.ct_attrs = tmp_attrs;

	/* initialize probe. */
	memset(tmp_probe, 0, sizeof(*tmp_probe));
	config_group_init_type_name(&tmp_probe->group, name, &type->item_type);
	/* Make sure that item is cleaned only when freeing it */
	config_item_get(&tmp_probe->group.cg_item);
	tmp_probe->group.default_groups = tmp_def;
	spin_lock_init(&tmp_probe->lock);
	tmp_probe->probe_period =
		msecs_to_jiffies(SCHEDULER_PROBE_DEFAULT_PERIOD);
	global_config_item_init(&tmp_probe->global_item,
				&scheduler_probe_drop_ops);

	return tmp_probe;

out_kmalloc:
	kfree(tmp_probe);
	kfree(tmp_attrs);
	kfree(tmp_def);

	return NULL;
}

/**
 * This function frees all the memory taken by a probe.
 * @author Marko Novak, Louis Rilling
 *
 * @param probe         pointer to probe whose memory we want to free.
 */
void scheduler_probe_free(struct scheduler_probe *probe)
{
	/*
	 * We have to do this here because probes cannot guarantee that they
	 * are not working before calling unregister.
	 */
	flush_scheduled_work();
	config_group_put(&probe->group);
	/*
	 * free all the structures that were allocated during
	 * scheduler_probe_create.
	 */
	kfree(probe->group.default_groups);
	kfree(scheduler_probe_type_of(probe)->item_type.ct_attrs);
	kfree(probe);
}

/**
 * Finds probe with a given name. Returns NULL if no such probe is found.
 *
 * Assumes probes_lock held.
 */
static struct scheduler_probe *probe_find(const char *name)
{
        struct list_head *pos;
        struct scheduler_probe *entry;

        list_for_each(pos, &probes_list) {
                entry = list_entry(pos, struct scheduler_probe, list);
                if (strcmp(name, scheduler_probe_name(entry)) == 0)
                        return entry;
        }

        return NULL;
}

/**
 * This function is used for registering probe. This function has to
 * be called at the end of "init_module" function for each probe's module.
 * @author Marko Novak, Louis Rilling
 *
 * @param probe         pointer to the probe we wish to register.
 *
 * @return      0, if probe was successfully registered.
 *              -EEXIST, if probe with same name is already registered.
 */
int scheduler_probe_register(struct scheduler_probe *probe)
{
	int ret = 0;

	spin_lock(&probes_lock);
	if (probe_find(scheduler_probe_name(probe)) != NULL)
		ret = -EEXIST;
	else
		/*
		 * ok, no probe with the same name exists, proceed with
		 * registration
		 */
		list_add(&probe->list, &probes_list);
	spin_unlock(&probes_lock);

	return ret;
}

/**
 * This function is used for removing probe registration. This function has to
 * be called from "cleanup_module" function for each probe's module.
 * @author Marko Novak, Louis Rilling
 *
 * @param probe         pointer to the probe we wish to unregister.
 */
void scheduler_probe_unregister(struct scheduler_probe *probe)
{
	spin_lock(&probes_lock);
	list_del(&probe->list);
	spin_unlock(&probes_lock);
}

/**
 * This is a configfs callback function, which is invoked every time user
 * tries to create directory in "/krg_scheduler/probes/" subdirectory. It
 * is used for loading probe's module, initializing and activating it.
 *
 * Note: the function is already synchronized since configfs takes care of
 * locking.
 */
static struct config_group *probes_make_group(struct config_group *group,
					      const char *name)
{
	struct config_group *ret;
	struct scheduler_probe *tmp_probe;
	struct scheduler_probe_type *type;
	struct string_list_object *global_probes = NULL;
	int err;

	ret = ERR_PTR(-EPERM);
	if (!(current->flags & PF_KTHREAD) && !current->nsproxy->krg_ns)
		goto out;

	if (!(current->flags & PF_KTHREAD)
	    && !IS_KERRIGHED_NODE(KRGFLAGS_RUNNING))
		goto out;

	global_probes = global_config_make_item_begin(&group->cg_item, name);
	if (IS_ERR(global_probes)) {
		ret = (void *)(global_probes);
		goto out;
	}

	spin_lock(&probes_lock);
	tmp_probe = probe_find(name);
	if (!tmp_probe) {
		spin_unlock(&probes_lock);

		/*
		 * insert probe's module into kernel space.
		 * Note: no module locking is needed, since module is already
		 * locked by "request_module".
		 *
		 * note: all the probes' files have to be copied into
		 * "/lib/modules/<version>/extra" directory and added
		 * to "/lib/modules/<version>/modules.dep" file.
		 */
		request_module("%s", name);

		spin_lock(&probes_lock);
		tmp_probe = probe_find(name);
	}

	/*
	 * if probe's module didn't manage to register itself, abort.
         * this usually implies an error at probe initialization
         * (in "init_module" function) or that module is already loaded
         * in the kernel and has to be manually unloaded first.
	 */
	err = -ENOENT;
	if (!tmp_probe)
		goto err_module;

	/*
	 * configfs does try_module_get a bit too late for us because we will
	 * already have scheduled probe refreshment.
	 */
	err = -EAGAIN;
	if (!try_module_get(tmp_probe->group.cg_item.ci_type->ct_owner))
		goto err_module;
	spin_unlock(&probes_lock);

	err = global_config_make_item_end(global_probes,
					  &group->cg_item,
					  &tmp_probe->global_item,
					  name);
	if (err) {
		module_put(tmp_probe->group.cg_item.ci_type->ct_owner);
		goto err;
	}

	config_group_get(&tmp_probe->group);

	/* perform measurement of resource properties for the first time. */
	type = scheduler_probe_type_of(tmp_probe);
	if (type->perform_measurement) {
		scheduler_probe_lock(tmp_probe);
		type->perform_measurement();
		scheduler_probe_unlock(tmp_probe);
		/* schedule next refreshment. */
		INIT_DELAYED_WORK(&tmp_probe->work, probe_refresh_func);
		schedule_delayed_work(&tmp_probe->work,
				      tmp_probe->probe_period);
	}

	ret = &tmp_probe->group;

out:
	return ret;

err_module:
	spin_unlock(&probes_lock);
	global_config_make_item_error(global_probes, name);
err:
	ret = ERR_PTR(err);
	goto out;
}

/**
 * Callback called by global_config when the probe is globally dropped
 */
static void scheduler_probe_drop(struct global_config_item *item)
{
	struct scheduler_probe *p = container_of(item,
						 struct scheduler_probe,
						 global_item);

	config_group_put(&p->group);
	module_put(p->group.cg_item.ci_type->ct_owner);
}

static int probes_allow_drop_item(struct config_group *group,
				  struct config_item *item)
{
	if (!(current->flags & PF_KTHREAD) && !current->nsproxy->krg_ns)
		return -EPERM;
	return 0;
}

/**
 * This is a configfs callback function, which is invoked every time user
 * tries to remove directory in "/krg_scheduler/probes/" subdirectory.
 * It is used for deactivating chosen probe.
 *
 * Note: the function is already synchronized since configfs takes care of
 * locking.
 */
static void probes_drop_item(struct config_group *group,
	struct config_item *item)
{
	struct scheduler_probe *p = to_scheduler_probe(item);

	if (scheduler_probe_type_of(p)->perform_measurement)
		cancel_rearming_delayed_work(&p->work);
	global_config_drop(&p->global_item);
}

/**
 * This struct is ConfigFS-specific. See ConfigFS documentation for its
 * explanation.
 */
static struct configfs_group_operations probes_group_ops = {
	.make_group = probes_make_group,
	.allow_drop_item = probes_allow_drop_item,
	.drop_item = probes_drop_item,
};

/**
 * This struct is ConfigFS-specific. See ConfigFS documentation for its
 * explanation.
 */
static struct config_item_type probes_type = {
	.ct_group_ops = &probes_group_ops,
	.ct_owner = THIS_MODULE,
};

/**
 * This struct is ConfigFS-specific. See ConfigFS documentation for its
 * explanation.
 */
static struct config_group probes_group = {
	.cg_item = {
		.ci_namebuf = PROBES_NAME,
		.ci_type = &probes_type,
	},
};

/**
 * Initializes list of probes and all ConfigFS infrastructure.
 * Registers "probes" subdirectory.
 * author Marko Novak, Louis Rilling
 */
struct config_group *scheduler_probe_start(void)
{
	/* initialize and register configfs subsystem. */
	config_group_init(&probes_group);
	return &probes_group;
}

/**
 * Unregisters "probes" subdirectory and all the ConfigFS infrastructure
 * related to probes.
 * @author Marko Novak, Louis Rilling
 */
void scheduler_probe_exit(void)
{
}

EXPORT_SYMBOL(scheduler_probe_register);
EXPORT_SYMBOL(scheduler_probe_unregister);
EXPORT_SYMBOL(scheduler_probe_create);
EXPORT_SYMBOL(scheduler_probe_free);
EXPORT_SYMBOL(scheduler_probe_source_create);
EXPORT_SYMBOL(scheduler_probe_source_free);
