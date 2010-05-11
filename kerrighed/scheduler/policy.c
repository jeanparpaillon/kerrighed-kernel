/*
 *  kerrighed/scheduler/policy.c
 *
 *  Copyright (C) 2007 Marko Novak - Xlab
 *  Copyright (C) 2007-2008 Louis Rilling - Kerlabs
 */

#include <linux/module.h>
#include <linux/nsproxy.h>
#include <linux/configfs.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <kerrighed/scheduler/global_config.h>
#include <kerrighed/scheduler/policy.h>

#include "internal.h"

/* a spinlock protecting access to the list of scheduling policy types */
static DEFINE_SPINLOCK(policies_lock);

/* list of registered scheduling policy types */
static LIST_HEAD(policies_list);

static
inline
struct scheduler_policy *to_scheduler_policy(struct config_item *item)
{
	return container_of(to_config_group(item),
			    struct scheduler_policy, group);
}

static
inline
struct scheduler_policy_attribute *
to_scheduler_policy_attr(struct configfs_attribute *attr)
{
	return container_of(attr, struct scheduler_policy_attribute, attr);
}

static
inline
struct scheduler_policy_type *
to_scheduler_policy_type(struct config_item_type *type)
{
	return container_of(type, struct scheduler_policy_type, item_type);
}

/**
 * General function for reading scheduling policies' ConfigFS attributes.
 * @author Marko Novak, Louis Rilling
 */
static ssize_t scheduler_policy_attribute_show(struct config_item *item,
					       struct configfs_attribute *attr,
					       char *page)
{
	struct scheduler_policy_attribute *policy_attr =
		to_scheduler_policy_attr(attr);
	struct scheduler_policy *policy = to_scheduler_policy(item);
	ssize_t ret = -EACCES;

	if (policy_attr->show) {
		spin_lock(&policy->lock);
		ret = policy_attr->show(policy, page);
		spin_unlock(&policy->lock);
	}

	return ret;
}

/**
 * General function for storing scheduling policies' ConfigFS attributes.
 * @author Marko Novak, Louis Rilling
 */
static ssize_t scheduler_policy_attribute_store(struct config_item *item,
						struct configfs_attribute *attr,
						const char *page, size_t count)
{
	struct scheduler_policy_attribute *policy_attr =
		to_scheduler_policy_attr(attr);
	struct scheduler_policy *policy = to_scheduler_policy(item);
	struct string_list_object *list = NULL;
	ssize_t ret = -EACCES;

	if (!(current->flags & PF_KTHREAD) && !current->nsproxy->krg_ns)
		return -EPERM;

	if (policy_attr->store) {
		if (!policy_attr->local) {
			list = global_config_attr_store_begin(item);
			if (IS_ERR(list))
				return PTR_ERR(list);
		}

		spin_lock(&policy->lock);
		ret = policy_attr->store(policy, page, count);
		spin_unlock(&policy->lock);

		if (!policy_attr->local) {
			if (ret >= 0)
				ret = global_config_attr_store_end(list,
								   item, attr,
								   page, ret);
			else
				global_config_attr_store_error(list, item);
		}
	}

	return ret;
}

static void scheduler_policy_release(struct config_item *);

static struct global_config_attrs *policy_global_attrs(struct config_item *item)
{
	return &to_scheduler_policy(item)->global_attrs;
}

/**
 * This struct is ConfigFS-specific. See ConfigFS documentation for its
 * explanation.
 */
struct global_config_item_operations policy_global_item_ops = {
	.config = {
		.release = scheduler_policy_release,
		.show_attribute = scheduler_policy_attribute_show,
		.store_attribute = scheduler_policy_attribute_store,
	},
	.global_attrs = policy_global_attrs,
};

/**
 * This function initializes a new scheduling policy.
 * @author Marko Novak, Louis Rilling
 *
 * @param policy	pointer to the scheduler_policy to init
 * @param name		name of the scheduling policy. This name must be the one
 *			provided as argument to the constructor.
 * @param type		type of the scheduler_policy
 * @param def_groups	NULL-terminated array of subdirs of the scheduler_policy
 *			directory, or NULL
 *
 * @return		0 if successul,
 *			-ENODEV is module is unloading (should not happen!),
 *			-ENOMEM if not sufficient memory could be allocated.
 */
int scheduler_policy_init(struct scheduler_policy *policy,
			  const char *name,
			  struct scheduler_policy_type *type,
			  struct config_group *def_groups[])
{
	struct config_group **tmp_groups = NULL;
	int nr_groups;
	int err;

	err = -ENODEV;
	if (!try_module_get(type->item_type.ct_owner))
		goto err_module;

	err = -ENOMEM;
	nr_groups = nr_def_groups(def_groups);
	if (nr_groups) {
		tmp_groups = kmalloc(sizeof(*tmp_groups) * (nr_groups + 1),
				     GFP_KERNEL);
		if (!tmp_groups)
			goto err_def_groups;
		memcpy(tmp_groups, def_groups,
		       sizeof(*tmp_groups) * (nr_groups + 1));
	}

	/* initialize scheduling policy. */
	memset(policy, 0, sizeof(struct scheduler_policy));
	config_group_init_type_name(&policy->group, name, &type->item_type);

	spin_lock_init(&policy->lock);

	policy->group.default_groups = tmp_groups;

	return 0;

err_def_groups:
	module_put(type->item_type.ct_owner);
err_module:
	return err;
}

void scheduler_policy_cleanup(struct scheduler_policy *policy)
{
	kfree(policy->group.default_groups);
}

/*
 * Configfs callback when the last reference on the scheduler_policy is dropped.
 * Destroys the scheduling policy.
 */
static void scheduler_policy_release(struct config_item *item)
{
	struct scheduler_policy_type *type =
		to_scheduler_policy_type(item->ci_type);
	struct scheduler_policy *policy = to_scheduler_policy(item);

	type->ops->destroy(policy);
	module_put(type->item_type.ct_owner);
}

/**
 * Finds scheduling policy type with a given name. Returns NULL if no such
 * scheduling policy type is registered.
 *
 * Assumes policies_lock held.
 */
static
struct scheduler_policy_type *scheduler_policy_type_find(const char *name)
{
	struct list_head *pos;
	struct scheduler_policy_type *entry;

	list_for_each(pos, &policies_list) {
		entry = list_entry(pos, struct scheduler_policy_type, list);
		if (strcmp(name, entry->name) == 0)
			return entry;
	}

	return NULL;
}

/**
 * Determines length of a NULL-terminated array
 */
static int scheduler_policy_attribute_array_length(
	struct scheduler_policy_attribute **attrs) {

	int i;
	if (!attrs)
		return 0;
	for (i=0; attrs[i] != NULL; i++)
		;
	return i;
}

/**
 * This function is used for registering newly added scheduling policy types.
 * Once a type is registered, new scheduling policies of this type can be
 * created when user does mkdir with the type name.
 * @author Marko Novak, Louis Rilling
 *
 * @param type		pointer to the scheduling policy type to register.
 *
 * @return		0 if successful,
 *			-EEXIST if scheduling policy type with the same name
 *				is already registered.
 */
int scheduler_policy_type_register(struct scheduler_policy_type *type)
{
	struct configfs_attribute **tmp_attrs = NULL;
	int num_attrs, i;
	int ret = 0;

	/* Fixup type */
	type->item_type.ct_item_ops = &policy_global_item_ops.config;

	num_attrs = scheduler_policy_attribute_array_length(type->attrs);
	if (num_attrs) {
		tmp_attrs = kmalloc(sizeof(*tmp_attrs) * (num_attrs + 1),
				    GFP_KERNEL);
		if (!tmp_attrs)
			return -ENOMEM;
		for (i = 0; i < num_attrs; i++)
			tmp_attrs[i] = &type->attrs[i]->attr;
		tmp_attrs[num_attrs] = NULL;
	}

	/* Try registering */
	spin_lock(&policies_lock);
	if (scheduler_policy_type_find(type->name) != NULL) {
		ret = -EEXIST;
	} else {
		/*
		 * ok, no scheduling policy with same name exists, proceed
		 * with registration.
		 */
		type->item_type.ct_attrs = tmp_attrs;
		list_add(&type->list, &policies_list);
	}
	spin_unlock(&policies_lock);
	if (ret)
		kfree(tmp_attrs);
	else
		printk(KERN_INFO
		       "successfully registered scheduler_policy_type %s\n",
		       type->name);

	return ret;
}

/**
 * This function is used for removing scheduling policy registrations.
 * Must *only* be called at module unloading.
 * @author Marko Novak, Louis Rilling
 *
 * @param type		pointer to the scheduling policy type to unregister.
 */
void scheduler_policy_type_unregister(struct scheduler_policy_type *type)
{
	spin_lock(&policies_lock);
	list_del(&type->list);
	spin_unlock(&policies_lock);

	kfree(type->item_type.ct_attrs);
	type->item_type.ct_attrs = NULL;
}

/**
 * Function to create and initilialize a scheduling policy having the type
 * named. The scheduling policy directory will be named after its type.
 * Called by whichever subsystem that creates scheduling policies.
 *
 * @param name		Type name of the scheduling policy
 *
 * @return		Pointer to the new scheduling policy, or
 *			NULL if failed
 */
struct scheduler_policy *scheduler_policy_new(const char *name)
{
	struct scheduler_policy_type *type;
	struct scheduler_policy *tmp_policy;
	int err;

	spin_lock(&policies_lock);
	type = scheduler_policy_type_find(name);
	if (!type) {
		spin_unlock(&policies_lock);

		/*
		 * insert scheduling policy's module into kernel space.
		 * Note: no module locking is needed, since module is already
		 * locked by "request_module".
		 *
		 * note: all the scheduling policies' files have to be copied
		 * into "/lib/modules/<version>/extra" directory and added to
		 * "/lib/modules/<version>/modules.dep" file.
		 */
		request_module("%s", name);

		spin_lock(&policies_lock);
		type = scheduler_policy_type_find(name);
	}

	/*
	 * if scheduling policy's module didn't manage to register itself,
	 * abort.
	 * this usually implies an error at scheduling policy type
	 * initialization (in "init_module" function) or that module
	 * is already loaded in the kernel and has to be manually
	 * unloaded first.
	 */
	err = -ENOENT;
	if (!type)
		goto err_module;

	/*
	 * configfs does try_module_get a bit too late for us because a user
	 * might remove the policy's module while type is a pointer still
	 * pointing to it.
	 */
	err = -EAGAIN;
	if (!try_module_get(type->item_type.ct_owner))
		goto err_module;
	spin_unlock(&policies_lock);

	tmp_policy = type->ops->new(name);
	module_put(type->item_type.ct_owner);
	if (!tmp_policy) {
		err = -ENOMEM;
		goto err;
	}

	return tmp_policy;

err_module:
	spin_unlock(&policies_lock);
err:
	return ERR_PTR(err);
}

/**
 * Callback to deactivate a scheduling policy when its directory is dropped.
 * Called by whichever subsystem that creates scheduling policies.
 *
 * @param policy	 The policy to drop
 */
void scheduler_policy_drop(struct scheduler_policy *policy)
{
	config_group_put(&policy->group);
}

EXPORT_SYMBOL(scheduler_policy_type_register);
EXPORT_SYMBOL(scheduler_policy_type_unregister);
EXPORT_SYMBOL(scheduler_policy_init);
EXPORT_SYMBOL(scheduler_policy_cleanup);
