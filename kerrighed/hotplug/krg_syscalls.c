/** Interface to create / remove Kerrighed syscalls.
 *  @file krg_syscalls.c
 *
 *  Copyright (C) 2001-2006, INRIA, Universite de Rennes 1, EDF.
 *  Copyright (C) 2009, Kerlabs
 */
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/nsproxy.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/hashtable.h>

#define MODULE_NAME "Syscalls interface"
#define DEBUG_THIS_MODULE

#include <kerrighed/debug.h>

#include <kerrighed/krg_syscalls.h>
#include <kerrighed/procfs.h>

#define PROC_HASH_TABLE_SIZE 256

struct proc_dir_entry *proc_services = NULL;

hashtable_t *proc_service_functions;

static int proc_services_ioctl(struct inode *inode, struct file *filp,
			       unsigned int cmd, unsigned long arg);
static ssize_t proc_services_read(struct file *, char *, size_t, loff_t *);

static struct file_operations proc_services_files_ops = {
	.ioctl = proc_services_ioctl,
	.read = proc_services_read,
};

/** IO Control for the file /proc/kerrighed/services.
 *  @author Renaud Lottiaux
 */
static int proc_services_ioctl(struct inode *inode, struct file *filp,
			       unsigned int cmd, unsigned long arg)
{
	struct proc_service_entry *service_entry;

	service_entry =
	    (struct proc_service_entry *)hashtable_find(proc_service_functions,
							cmd);

	if (service_entry != NULL) {
		if (service_entry->restricted && !current->nsproxy->krg_ns)
			return -EPERM;
		service_entry->count++;
		return service_entry->fct((void *)arg);
	}
#ifdef CONFIG_KRG_DEBUG
	PANIC("Kerrighed command %d-%d (0x%08x) unknown\n", cmd & 0xE0,
	      cmd & 0x1F, cmd);
#endif

	return -EINVAL;
}

static ssize_t proc_services_read(struct file *f, char *buff,
				  size_t count, loff_t * off)
{
	int index;
	ssize_t ret;

	printk("proc_service_read: start - count=%ld\n", (long)count);

	ret = 0;

	for (index = 0;
	     (index < proc_service_functions->hashtable_size) && (count >= 50);
	     index++) {
		struct hash_list *ht;
		struct proc_service_entry *se;

		se = proc_service_functions->table[index].data;
		if (se != NULL) {
			printk("%s: %lu\n", se->label, se->count);

			for (ht = proc_service_functions->table[index].next;
			     (ht != NULL) && (count >= 50); ht = ht->next) {
				int l;
				se = ht->data;
				printk("%s: %lu\n", se->label, se->count);
				l = sprintf(buff + ret, "%s: %lu\n", se->label,
					    se->count);
				count -= l;
				ret += l;
			};
		};
	};

	printk("proc_service_read: stop - (count=%ld)\n", (long)ret);
	return ret;
};

/** Add a service to the /proc/kerrighed/services
 *  @author Renaud Lottiaux
 *
 *  @param cmd   Identifier of the service.
 *  @param fun   Service function.
 */
int __register_proc_service(unsigned int cmd, proc_service_function_t fun,
			    bool restricted)
{
	struct proc_service_entry *service_entry;

	service_entry =
	    (struct proc_service_entry *)hashtable_find(proc_service_functions,
							cmd);
	if (service_entry != NULL && fun != NULL) {
		PANIC("Kerrighed command %d-%d (0x%08x) already registered\n",
		      cmd & 0xE0, cmd & 0x1F, cmd);
		return -1;
	}

	service_entry = kmalloc(sizeof(struct proc_service_entry), GFP_KERNEL);

	service_entry->fct = fun;
	sprintf(service_entry->label, "%d-%d (0x%08x)",
		cmd & 0xE0, cmd & 0x1F, cmd);
	service_entry->count = 0;
	service_entry->restricted = restricted;

	hashtable_add(proc_service_functions, cmd, service_entry);
	return 0;
}

int register_proc_service(unsigned int cmd, proc_service_function_t fun)
{
	return __register_proc_service(cmd, fun, true);
}
EXPORT_SYMBOL(register_proc_service);

/** Remove a service from the /proc/kerrighed/services
 *  @author Renaud Lottiaux
 *
 *  @param cmd   Identifier of the service.
 */
int unregister_proc_service(unsigned int cmd)
{
	if (hashtable_remove(proc_service_functions, cmd) == NULL)
		return -EINVAL;

	return 0;
}
EXPORT_SYMBOL(unregister_proc_service);

/** Initialisation of the /proc/kerrighed/services file.
 *  @author Renaud Lottiaux
 */
int krg_syscalls_init(void)
{
	int err = 0;

	printk("Init kerrighed syscall mechanism\n");

	/* Create the /proc/kerrighed/services */

	proc_services = create_proc_entry("services", 0644, proc_kerrighed);
	if (proc_services == NULL)
		err = -EMFILE;
	else {
		proc_service_functions = hashtable_new(PROC_HASH_TABLE_SIZE);
		proc_services->proc_fops = &proc_services_files_ops;
	}

	return err;
}

/** Destroy of the /proc/kerrighed/services file.
 *  @author Renaud Lottiaux
 */
int krg_syscalls_finalize(void)
{
	remove_proc_entry("services", proc_kerrighed);

	hashtable_free(proc_service_functions);

	return 0;
}
