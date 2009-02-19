/*
 *  Copyright (C) 2006-2007, Pascal Gallard, Kerlabs.
 */

#define MODULE_NAME "Hotplug"

#include <linux/reboot.h>
#include <linux/fs.h>
#include <linux/workqueue.h>
#include <linux/sched.h>
#include <linux/irqflags.h>
#include <kerrighed/krgnodemask.h>
#include <kerrighed/sys/types.h>
#include <kerrighed/krginit.h>
#include <asm/uaccess.h>

#include <kerrighed/krg_services.h>
#include <kerrighed/krg_syscalls.h>
#include <net/krgrpc/rpcid.h>
#include <net/krgrpc/rpc.h>

#include "hotplug.h"
#include "hotplug_internal.h"

krgnodemask_t failure_vector;
struct work_struct fail_work;
struct work_struct recovery_work;
struct notifier_block *hotplug_failure_notifier_list;

static void recovery_worker(struct work_struct *data)
{
	kerrighed_node_t i;

	for_each_krgnode_mask(i, failure_vector){
		clear_krgnode_online(i);
		printk("FAILURE OF %d DECIDED\n", i);
		printk("should ignore messages from this node\n");
	}

	//knetdev_failure(&failure_vector);
	//comm_failure(&failure_vector);

#ifdef CONFIG_KRG_CTNR
	//ctnr_failure(&failure_vector);
#endif
}

void krg_failure(krgnodemask_t * vector)
{

	if(__krgnodes_equal(&failure_vector, vector))
		return;
	
	__krgnodes_copy(&failure_vector, vector);

	queue_work(krg_ha_wq, &recovery_work);
}

static void handle_node_fail(struct rpc_desc *desc, void *data, size_t size)
{
	emergency_sync();
	emergency_remount();

	set_current_state(TASK_INTERRUPTIBLE);
	schedule_timeout(5 * HZ);

	local_irq_enable();
	machine_restart(NULL);

	// should never be reached
	BUG();

}

static int nodes_fail(void *arg)
{
	struct __hotplug_node_set __node_set;
	struct hotplug_node_set node_set;
	int unused;
	
	if (copy_from_user(&node_set, arg, sizeof(__node_set)))
		return -EFAULT;

	node_set.subclusterid = __node_set.subclusterid;

	if (krgnodemask_copy_from_user(&node_set.v, &__node_set.v))
		return -EFAULT;
	
	rpc_async_m(NODE_FAIL, &node_set.v,
		    &unused, sizeof(unused));
	
	return 0;
}

int hotplug_failure_init(void)
{
	INIT_WORK(&recovery_work, recovery_worker);

	rpc_register_void(NODE_FAIL, handle_node_fail, 0);
	
	register_proc_service(KSYS_HOTPLUG_FAIL, nodes_fail);

	return 0;
}

void hotplug_failure_cleanup(void)
{
}
