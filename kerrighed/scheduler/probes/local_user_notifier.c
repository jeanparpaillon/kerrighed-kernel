/**
 * Kerrighed -- Local user presence notifier
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
MODULE_DESCRIPTION("Local user presence notification interface for /proc");
MODULE_VERSION("1.0");

static struct proc_dir_entry * root;

#define LOCAL_USER_NOTIFIER_PROC_ROOT		"kerrighed/interactive_user"
#define LOCAL_USER_NOTIFIER_PROC_GET		"get"
#define LOCAL_USER_NOTIFIER_PROC_ISFREE		"isfree"
#define LOCAL_USER_NOTIFIER_PROC_ISUSED		"isused"
#define LOCAL_USER_NOTIFIER_PROC_CONNECTION	"connection"
#define LOCAL_USER_NOTIFIER_PROC_DISCONNECTION	"disconnection"

static int local_user_notifier_user_connection(struct file *file, const char __user *buffer, unsigned long count, void *data);
static int local_user_notifier_user_disconnection(struct file *file, const char __user *buffer, unsigned long count, void *data);
static int local_user_notifier_user_connected(char *page, char **start, off_t offset, int count, int *eof, void *data);
static int local_user_notifier_node_free(char *page, char **start, off_t offset, int count, int *eof, void *data);
static int local_user_notifier_node_used(char *page, char **start, off_t offset, int count, int *eof, void *data);

static int __proc_init(void);
static void __proc_exit(void);
static int __init local_user_notifier_init(void);
static void __exit local_user_notifier_exit(void);

static int local_user_notifier_user_connection(struct file *file, const char __user *buffer, unsigned long count, void *data)
{
	local_user_presence_user_connection();
	return count;
}

static int local_user_notifier_user_disconnection(struct file *file, const char __user *buffer, unsigned long count, void *data)
{
	local_user_presence_user_disconnection();
	return count;
}

static int local_user_notifier_user_connected(char *page, char **start, off_t offset, int count, int *eof, void *data)
{
	int len = 0;
	len += sprintf(page + len, "%u\n", local_user_presence_user_connected());
	return len;
}

static int local_user_notifier_node_free(char *page, char **start, off_t offset, int count, int *eof, void *data)
{
	int len = 0;
	len += sprintf(page + len, "%u\n", local_user_presence_node_free());
	return len;
}

static int local_user_notifier_node_used(char *page, char **start, off_t offset, int count, int *eof, void *data)
{
	int len = 0;
	len += sprintf(page + len, "%u\n", local_user_presence_node_used());
	return len;
}

static int __proc_init(void)
{
	struct proc_dir_entry *p;

	/* /proc/kerrighed/interactive_user : dr-xr-xr-x */
	root = create_proc_entry(LOCAL_USER_NOTIFIER_PROC_ROOT, S_IFDIR | S_IRUGO | S_IXUGO, NULL);
	if (!root)
		goto err_root;

	/* /proc/kerrighed/interactive_user/get : -r--r--r-- */
	p = create_proc_read_entry(LOCAL_USER_NOTIFIER_PROC_GET, S_IFREG | S_IRUGO, root, local_user_notifier_user_connected, NULL);
	if (!p)
		goto err_get;

	/* /proc/kerrighed/interactive_user/isfree : -r--r--r-- */
	p = create_proc_read_entry(LOCAL_USER_NOTIFIER_PROC_ISFREE, S_IFREG | S_IRUGO, root, local_user_notifier_node_free, NULL);
	if (!p)
		goto err_isfree;

	/* /proc/kerrighed/interactive_user/isused : -r--r--r-- */
	p = create_proc_read_entry(LOCAL_USER_NOTIFIER_PROC_ISUSED, S_IFREG | S_IRUGO, root, local_user_notifier_node_used, NULL);
	if (!p)
		goto err_isused;

	/* /proc/kerrighed/interactive_user/connection : --w--w--w- */
	p = create_proc_entry(LOCAL_USER_NOTIFIER_PROC_CONNECTION, S_IFREG | S_IWUGO, root);
	if (!p)
		goto err_connection;

	p->write_proc = local_user_notifier_user_connection;

	/* /proc/kerrighed/interactive_user/disconnection : --w--w--w- */
	p = create_proc_entry(LOCAL_USER_NOTIFIER_PROC_DISCONNECTION, S_IFREG | S_IWUGO, root);
	if (!p)
		goto err_disconnection;

	p->write_proc = local_user_notifier_user_disconnection;

	return 0;

err_disconnection:
	printk(KERN_ERR "Cannot create proc entry %s\n", LOCAL_USER_NOTIFIER_PROC_DISCONNECTION);
	remove_proc_entry(LOCAL_USER_NOTIFIER_PROC_CONNECTION, root);
err_connection:
	printk(KERN_ERR "Cannot create proc entry %s\n", LOCAL_USER_NOTIFIER_PROC_CONNECTION);
	remove_proc_entry(LOCAL_USER_NOTIFIER_PROC_ISUSED, root);
err_isused:
	printk(KERN_ERR "Cannot create proc entry %s\n", LOCAL_USER_NOTIFIER_PROC_ISUSED);
	remove_proc_entry(LOCAL_USER_NOTIFIER_PROC_ISFREE, root);
err_isfree:
	printk(KERN_ERR "Cannot create proc entry %s\n", LOCAL_USER_NOTIFIER_PROC_ISFREE);
	remove_proc_entry(LOCAL_USER_NOTIFIER_PROC_GET, root);
err_get:
	printk(KERN_ERR "Cannot create proc entry %s\n", LOCAL_USER_NOTIFIER_PROC_GET);
	remove_proc_entry(LOCAL_USER_NOTIFIER_PROC_ROOT, NULL);
err_root:
	printk(KERN_ERR "Cannot create proc entry %s\n", LOCAL_USER_NOTIFIER_PROC_ROOT);
	return -EAGAIN;
}

static void __proc_exit(void)
{
	remove_proc_entry(LOCAL_USER_NOTIFIER_PROC_GET, root);
	remove_proc_entry(LOCAL_USER_NOTIFIER_PROC_ISFREE, root);
	remove_proc_entry(LOCAL_USER_NOTIFIER_PROC_ISUSED, root);
	remove_proc_entry(LOCAL_USER_NOTIFIER_PROC_CONNECTION, root);
	remove_proc_entry(LOCAL_USER_NOTIFIER_PROC_DISCONNECTION, root);
	remove_proc_entry(LOCAL_USER_NOTIFIER_PROC_ROOT, NULL);
}

static int __init local_user_notifier_init(void)
{
	int retval;

	printk(KERN_INFO "Loading Local User Presence Notification Interface module ...\n");

	retval = __proc_init();
	if (retval >= 0)
		printk(KERN_INFO "Local User Presence Notification Interface module loaded.\n");
	else
		printk(KERN_ERR "Error while creating proc tree.\n");

	return retval;
}

static void __exit local_user_notifier_exit(void)
{
	printk(KERN_INFO "Unloading Local User Presence Notification Interface module.\n");

	__proc_exit();

	printk(KERN_INFO "Successfull unload of Local User Presence Notification Interface module.\n");
}

module_init(local_user_notifier_init);
module_exit(local_user_notifier_exit);
