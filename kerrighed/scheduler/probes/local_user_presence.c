/**
 * Kerrighed -- Local user presence counter
 *
 * Copyright (c) 2009 - Alexandre Lissy <alexandre.lissy@etu.univ-tours.fr>
 **/

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/mutex.h>
#include "local_user_presence.h"

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Alexandre Lissy <alexandre.lissy@etu.univ-tours.fr>");
MODULE_DESCRIPTION("Local user presence notification");
MODULE_VERSION("1.0");

static DEFINE_MUTEX(local_user_presence_lock);
static unsigned int local_user_presence_value;

static int __init local_user_presence_init(void);
static void __exit local_user_presence_exit(void);

void local_user_presence_user_connection(void)
{
	mutex_lock(&local_user_presence_lock);

	local_user_presence_value++;

	mutex_unlock(&local_user_presence_lock);
}
EXPORT_SYMBOL(local_user_presence_user_connection);

void local_user_presence_user_disconnection(void)
{
	mutex_lock(&local_user_presence_lock);

	if(local_user_presence_value > 0)
		local_user_presence_value--;

	mutex_unlock(&local_user_presence_lock);
}
EXPORT_SYMBOL(local_user_presence_user_disconnection);

unsigned int local_user_presence_user_connected(void)
{
	unsigned int val;

	mutex_lock(&local_user_presence_lock);

	val = local_user_presence_value;

	mutex_unlock(&local_user_presence_lock);

	return val;
}
EXPORT_SYMBOL(local_user_presence_user_connected);

unsigned int local_user_presence_node_free(void)
{
	unsigned int val;

	mutex_lock(&local_user_presence_lock);

	val = local_user_presence_value;

	mutex_unlock(&local_user_presence_lock);

	return (val == 0);
}
EXPORT_SYMBOL(local_user_presence_node_free);

unsigned int local_user_presence_node_used(void)
{
	unsigned int val;

	mutex_lock(&local_user_presence_lock);

	val = local_user_presence_value;

	mutex_unlock(&local_user_presence_lock);

	return (val > 0);
}
EXPORT_SYMBOL(local_user_presence_node_used);

static int __init local_user_presence_init(void)
{
	printk(KERN_INFO "Loading Local User Presence Notification module ...\n");

	mutex_lock(&local_user_presence_lock);

	local_user_presence_value = 0;

	mutex_unlock(&local_user_presence_lock);

	printk(KERN_INFO "Local User Presence Notification module loaded. Current value is 0.\n");

	return 0;
}

static void __exit local_user_presence_exit(void)
{
	printk(KERN_INFO "Unloading Local User Presence Notification module.\n");
}

module_init(local_user_presence_init);
module_exit(local_user_presence_exit);
