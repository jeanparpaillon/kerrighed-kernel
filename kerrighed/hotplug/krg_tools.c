/** Initilize the tool module.
 *  @file krg_tools.c
 *
 *  Copyright (C) 2006-2009, Pascal Gallard, Kerlabs.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <kerrighed/sys/types.h>
#include <kerrighed/krginit.h>
#include <asm/uaccess.h>

#include <kerrighed/procfs.h>
#include <kerrighed/krg_syscalls.h>
#include <kerrighed/krg_services.h>

static int tools_proc_nb_max_nodes(void* arg)
{
	int r, v = KERRIGHED_MAX_NODES;

	r = 0;
	
	if(copy_to_user((void*)arg, (void*)&v, sizeof(v)))
		r = -EFAULT;

	return r;
}

static int tools_proc_nb_max_clusters(void* arg)
{
	int r, v = KERRIGHED_MAX_CLUSTERS;

	r = 0;

	if(copy_to_user((void*)arg, (void*)&v, sizeof(v)))
		r = -EFAULT;

	return r;
}

static int tools_proc_node_id(void *arg)
{
        int node_id = kerrighed_node_id;
        int r = 0;

        if (copy_to_user((void *)arg, (void *)&node_id, sizeof(int)))
                r = -EFAULT;

        return r;
}

static int tools_proc_nodes_count(void *arg)
{
        int nb_nodes = num_online_krgnodes();
        int r = 0;

        if (copy_to_user((void *)arg, (void *)&nb_nodes, sizeof(int)))
                r = -EFAULT;

        return r;
}

int init_tools(void)
{
	int error;

	if ((error = kerrighed_proc_init()))
		goto ErrorProc;
	if ((error = krg_syscalls_init()))
		goto ErrorSys;

	error = register_proc_service(KSYS_NB_MAX_NODES, tools_proc_nb_max_nodes);
	if (error != 0) {
		error = -EINVAL;
		goto Error;
	}

	error = register_proc_service(KSYS_NB_MAX_CLUSTERS, tools_proc_nb_max_clusters);
	if (error != 0) {
		error = -EINVAL;
		goto Error;
	}

	error = register_proc_service(KSYS_GET_NODE_ID, tools_proc_node_id);
	if (error != 0) {
		error = -EINVAL;
		goto Error;
	}

	error = register_proc_service(KSYS_GET_NODES_COUNT, tools_proc_nodes_count);
	if (error != 0) {
		error = -EINVAL;
		goto Error;
	}
	
	printk("Kerrighed tools - init module\n");
 Done:
	return error;

	krg_syscalls_finalize();
 ErrorSys:
	kerrighed_proc_finalize();
 ErrorProc:
 Error:
	goto Done;
}
EXPORT_SYMBOL(init_tools);

void cleanup_tools(void)
{
	krg_syscalls_finalize();
#ifdef CONFIG_KERRIGHED
	kerrighed_proc_finalize();
#endif

	printk("iluvatar - end module\n");
}
