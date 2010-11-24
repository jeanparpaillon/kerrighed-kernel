/*
 *  kerrighed/scheduler/core.c
 *
 *  Copyright (C) 2007 Marko Novak - Xlab
 *  Copyright (C) 2007-2008 Louis Rilling - Kerlabs
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/configfs.h>
#include <kerrighed/hotplug.h>
#include <kerrighed/scheduler/process_set.h>

#include "internal.h"

static struct config_item_type krg_scheduler_type = {
	.ct_owner = THIS_MODULE,
};

struct configfs_subsystem krg_scheduler_subsys = {
	.su_group = {
		.cg_item = {
			.ci_namebuf = "krg_scheduler",
			.ci_type = &krg_scheduler_type,
		}
	}
};

static int add(struct hotplug_context *ctx)
{
	return global_config_add(ctx);
}

static int remove_local(struct hotplug_context *ctx)
{
	int err;

	err = scheduler_remove(ctx);
	if (err)
		return err;
	return global_config_remove_local(ctx);
}

static int remove_distant(struct hotplug_context *ctx)
{
	return global_config_remove(ctx);
}

static int remove_advert(struct hotplug_context *ctx)
{
	return scheduler_remove(ctx);
}

static int hotplug_notifier(struct notifier_block *nb,
			    hotplug_event_t event,
			    void *data)
{
	struct hotplug_context *ctx = data;
	int err;

	switch(event){
	case HOTPLUG_NOTIFY_ADD:
		err = add(ctx);
		break;
	case HOTPLUG_NOTIFY_REMOVE_LOCAL:
		err = remove_local(ctx);
		break;
	case HOTPLUG_NOTIFY_REMOVE_DISTANT:
		err = remove_distant(ctx);
		break;
	case HOTPLUG_NOTIFY_REMOVE_ADVERT:
		err = remove_advert(ctx);
		break;
	default:
		err = 0;
		break;
	}

	if (err)
		return notifier_from_errno(err);
	return NOTIFY_OK;
}

static int post_add(struct hotplug_context *ctx)
{
	int err;

	err = scheduler_post_add(ctx);
	if (err)
		return err;
	return global_config_post_add(ctx);
}

static int post_hotplug_notifier(struct notifier_block *nb,
				 hotplug_event_t event,
				 void *data)
{
	struct hotplug_context *ctx = data;
	int err;

	switch(event){
	case HOTPLUG_NOTIFY_ADD:
		err = post_add(ctx);
		break;
	default:
		err = 0;
		break;
	}

	if (err)
		return notifier_from_errno(err);
	return NOTIFY_OK;
}

int init_scheduler(void)
{
	int ret;
	struct config_group **defs = NULL;

	/* per task informations framework */
	ret = krg_sched_info_start();
	if (ret)
		goto err_krg_sched_info;

	/* initialize global mechanisms to replicate configfs operations */
	ret = string_list_start();
	if (ret)
		goto err_string_list;
	ret = global_config_start();
	if (ret)
		goto err_global_config;
	ret = remote_pipe_start();
	if (ret)
		goto err_remote_pipe;

	/* initialize and register configfs subsystem. */
	config_group_init(&krg_scheduler_subsys.su_group);
	mutex_init(&krg_scheduler_subsys.su_mutex);

	/* add probes, sched_policies to scheduler. */
	defs = kcalloc(3, sizeof (struct config_group *), GFP_KERNEL);

	if (defs == NULL) {
		printk(KERN_ERR "[%s] error: cannot allocate memory!\n",
			"scheduler_module_init");
		ret = -ENOMEM;
		goto err_kcalloc;
	}

	/* initialize probes and scheduling policies subgroup. */
	defs[0] = scheduler_probe_start();
	defs[1] = scheduler_start();
	defs[2] = NULL;

	if (defs[0]==NULL || defs[1]==NULL) {
		printk(KERN_ERR "[%s] error: Could not initialize one of the"
			" subgroups!\n", __PRETTY_FUNCTION__);
		ret = -EFAULT;
		goto err_init;
	}

	krg_scheduler_subsys.su_group.default_groups = defs;

	ret = configfs_register_subsystem(&krg_scheduler_subsys);

	if (ret) {
		printk(KERN_ERR "[%s] error %d: cannot register subsystem!\n",
			__PRETTY_FUNCTION__, ret);
		goto err_register;
	}

	ret = register_hotplug_notifier(hotplug_notifier,
					HOTPLUG_PRIO_SCHED);
	if (ret)
		goto err_hotplug;

	ret = register_hotplug_notifier(post_hotplug_notifier,
					HOTPLUG_PRIO_SCHED_POST);
	if (ret)
		goto err_hotplug;

	printk(KERN_INFO "scheduler initialization succeeded!\n");
	return 0;

err_hotplug:

	configfs_unregister_subsystem(&krg_scheduler_subsys);
err_register:

err_init:
	if (defs[1])
		scheduler_exit();
	if (defs[0])
		scheduler_probe_exit();
	kfree(defs);
err_kcalloc:

	remote_pipe_exit();
err_remote_pipe:

	global_config_exit();
err_global_config:

	string_list_exit();
err_string_list:

	krg_sched_info_exit();
err_krg_sched_info:

	return ret;
}

void cleanup_scheduler(void)
{
}
