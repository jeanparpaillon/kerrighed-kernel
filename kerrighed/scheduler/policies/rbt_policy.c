/*
 *  Copyright (C) 2009 Alexandre Lissy <alexandre.lissy@etu.univ-tours.fr>
 *
 * RBT is Copyright (c) 2008 - Matthieu Pérotin.
 * More informations available at :
 * http://portail.scd.univ-tours.fr/search*frf/X?PEROTIN,%20MATTHIEU&m=t&m=u
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/workqueue.h>
#include <linux/nodemask.h>
#include <linux/cpumask.h>

#include <kerrighed/capabilities.h>
#include <kerrighed/krginit.h>
#include <kerrighed/krgnodemask.h>
#include <kerrighed/pid.h>
#include <kerrighed/sys/types.h>
#include <kerrighed/migration.h>
#include <kerrighed/scheduler/policy.h>
#include <kerrighed/scheduler/port.h>
#include <kerrighed/scheduler/scheduler.h>
#include <kerrighed/scheduler/process_set.h>

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Alexandre Lissy <alexandre.lissy@etu.univ-tours.fr>");
MODULE_DESCRIPTION("RBT 'Arrosoir' Scheduling policy");

/* Use this to enable/disable verbose DEBUG output */
/* #define RBT_DEBUG 1 */

#ifdef RBT_DEBUG
#define rbt_debug(format, ...) printk(KERN_DEBUG "{RBT}:%s: " format, __PRETTY_FUNCTION__, __VA_ARGS__)
#else
#define rbt_debug(format, ...)
#endif

struct rbt_policy {
	struct scheduler_policy policy;
	struct delayed_work rbt_work;
	struct scheduler_port port_mattload;
	struct scheduler_port port_active_tasks;
	struct scheduler_port port_loadinc;
	struct scheduler_port port_process_jiffies;
	struct scheduler_port port_process_size;
	unsigned long rbt_exec_freq;
	unsigned long rbt_load_diff;
};

static ssize_t rbt_exec_freq_attr_show (struct scheduler_policy *, char *);
static ssize_t rbt_exec_freq_attr_store (struct scheduler_policy *, const char *, size_t);
static ssize_t rbt_load_diff_attr_show (struct scheduler_policy *, char *);
static ssize_t rbt_load_diff_attr_store (struct scheduler_policy *, const char *, size_t);

static struct scheduler_policy_attribute rbt_attr_freq = {
	.attr = {
		.ca_owner = THIS_MODULE,
		.ca_name = "rbt_exec_freq",
		.ca_mode = S_IRUGO | S_IWUSR,
	},
	.show = rbt_exec_freq_attr_show,
	.store = rbt_exec_freq_attr_store,
	.local = 1,
};

static struct scheduler_policy_attribute rbt_attr_diff = {
	.attr = {
		.ca_owner = THIS_MODULE,
		.ca_name = "rbt_load_diff",
		.ca_mode = S_IRUGO | S_IWUSR,
	},
	.show = rbt_load_diff_attr_show,
	.store = rbt_load_diff_attr_store
};

static struct scheduler_policy_attribute *rbt_policy_attrs[] = {
	&rbt_attr_freq,
	&rbt_attr_diff,
	NULL,
};

static struct scheduler_policy * rbt_policy_new(const char *name);
static void rbt_policy_destroy(struct scheduler_policy *policy);
static kerrighed_node_t rbt_policy_new_task_node(struct scheduler_policy *policy, struct task_struct *parent);

static struct scheduler_policy_operations rbt_policy_ops = {
	.new = rbt_policy_new,
	.destroy = rbt_policy_destroy,
	.new_task_node = rbt_policy_new_task_node,
};

static SCHEDULER_POLICY_TYPE(rbt_policy_type, "rbt_policy",
			     &rbt_policy_ops, rbt_policy_attrs);

/* Functions */
static void rbt_policy_exec(struct work_struct *w);
static struct task_struct * rbt_find_a_task(struct scheduler_policy *policyPtr);
static unsigned int * rbt_calc_ideal_load(const krgnodemask_t online_selected_nodes, int *upper_bound, struct rbt_policy *p);
static kerrighed_node_t rbt_find_a_node(kerrighed_node_t *next, unsigned int *idealLoads, struct scheduler_policy *policyPtr, const krgnodemask_t online_selected_nodes);
void check_node_id(kerrighed_node_t node);
static void toggle_next_node(kerrighed_node_t *nextNode, const krgnodemask_t online_selected_nodes);
static struct scheduler_policy * rbt_policy_new(const char *name);
static void rbt_policy_destroy(struct scheduler_policy *policy);
int __init rbt_policy_init(void);
void __exit rbt_policy_exit(void);

static BEGIN_SCHEDULER_PORT_TYPE(port_mattload),
	.SCHEDULER_PORT_VALUE_TYPE(port_mattload, unsigned int),
END_SCHEDULER_PORT_TYPE(port_mattload);

static BEGIN_SCHEDULER_PORT_TYPE(port_active_tasks),
	.SCHEDULER_PORT_VALUE_TYPE(port_active_tasks, unsigned long),
END_SCHEDULER_PORT_TYPE(port_active_tasks);

static BEGIN_SCHEDULER_PORT_TYPE(port_loadinc),
	.SCHEDULER_PORT_VALUE_TYPE(port_loadinc, unsigned int),
END_SCHEDULER_PORT_TYPE(port_loadinc);

static BEGIN_SCHEDULER_PORT_TYPE(port_process_jiffies),
	.SCHEDULER_PORT_VALUE_TYPE(port_process_jiffies, unsigned int),
	.SCHEDULER_PORT_PARAM_TYPE(port_process_jiffies, pid_t),
END_SCHEDULER_PORT_TYPE(port_process_jiffies);

static BEGIN_SCHEDULER_PORT_TYPE(port_process_size),
	.SCHEDULER_PORT_VALUE_TYPE(port_process_size, unsigned long),
	.SCHEDULER_PORT_PARAM_TYPE(port_process_size, pid_t),
END_SCHEDULER_PORT_TYPE(port_process_size);

static ssize_t rbt_exec_freq_attr_show (struct scheduler_policy *probe, char *page)
{
	struct rbt_policy *p = container_of(probe, struct rbt_policy, policy);

	return sprintf(page, "%lu\n", p->rbt_exec_freq);
}

static ssize_t rbt_exec_freq_attr_store (struct scheduler_policy *probe, const char *page, size_t count)
{
	struct rbt_policy *p = container_of(probe, struct rbt_policy, policy);

	if (strict_strtoul(page, 0, &p->rbt_exec_freq) < 0)
		return -EINVAL;

	return count;
}

static ssize_t rbt_load_diff_attr_show (struct scheduler_policy *probe, char *page)
{
	struct rbt_policy *p = container_of(probe, struct rbt_policy, policy);

	return sprintf(page, "%lu\n", p->rbt_load_diff);
}

static ssize_t rbt_load_diff_attr_store (struct scheduler_policy *probe, const char *page, size_t count)
{
	struct rbt_policy *p = container_of(probe, struct rbt_policy, policy);

	if (strict_strtoul(page, 0, &p->rbt_load_diff) < 0)
		return -EINVAL;

	return count;
}

unsigned int *rbt_calc_ideal_load(const krgnodemask_t online_selected_nodes, int *upper_bound, struct rbt_policy *p)
{
	unsigned int *load_increments;
	unsigned int *ideal_loads = NULL;
	unsigned long total_active_tasks = 0;
	unsigned long cur_active_tasks = 0;
	unsigned int loadinc = 0;
	int err;
	int nr_online_nodes;
	kerrighed_node_t cur_node = kerrighed_node_id;
	kerrighed_node_t node;
	unsigned int k, ideal_load, best_load, i_best_load = 0;
	unsigned int how_many, mattload_value;

	nr_online_nodes = krgnodes_weight(online_selected_nodes);

	load_increments = kzalloc(sizeof(unsigned int) * KERRIGHED_MAX_NODES, GFP_ATOMIC);
	if (!load_increments) {
		printk(KERN_ERR "rbt_calc_ideal_load: Cannot allocate load_increments.\n");
		goto err_alloc_load_increments;
	}

	ideal_loads = kzalloc(sizeof(unsigned int) * KERRIGHED_MAX_NODES, GFP_ATOMIC);
	if (!ideal_loads) {
		printk(KERN_ERR "rbt_calc_ideal_load: Cannot allocate ideal_loads.\n");
		goto err_alloc_ideal_loads;
	}

	__for_each_krgnode_mask(node, &online_selected_nodes) {
		/* Compute total load */
		err = scheduler_port_get_remote_value(
			&p->port_active_tasks,
			node,
			&cur_active_tasks,
			1, NULL, 0);
		if (err < 0) {
			printk(KERN_ERR "rbt_calc_ideal_load: Error %d while getting remote port 'active_tasks' value.\n", err);
			goto err_active_tasks;
		}

		/* Prepare load increments */
		err = scheduler_port_get_remote_value(
			&p->port_loadinc,
			node,
			&loadinc,
			1, NULL, 0);
		if (err < 0) {
			printk(KERN_ERR "rbt_calc_ideal_load: Error %d while getting remote port 'load_inc' value.\n", err);
			goto err_loadinc;
		}

		total_active_tasks += cur_active_tasks;
		load_increments[node] = loadinc;
		rbt_debug("Setting load_increments[%d]=%u (at %p)\n", node, loadinc, &load_increments[node]);
		/* Initialize ideals loads */
		ideal_loads[node] = 0;
	}

	/* printk(KERN_INFO "rbt_calc_ideal_load[%d]: total_active_tasks=%lu\n", cur_node, totalActiveTasks); */

	for (k = 0; k < total_active_tasks; k++) {
		/* /include/linux/kernel.h#L25 */
		best_load = UINT_MAX;

		for_each_online_krgnode(node) {
			if (ideal_loads[node] + load_increments[node] < best_load) {
				best_load = ideal_loads[node] + load_increments[node];
				i_best_load = node;
			}
		}

	        ideal_loads[i_best_load] = best_load;
		rbt_debug("Setting ideal_loads[%d]=%u (at %p)\n", i_best_load, best_load, &ideal_loads[i_best_load]);
	}

	err = scheduler_port_get_value(
		&p->port_mattload,
		&mattload_value,
		1, NULL, 0);
	if (err < 0) {
		printk(KERN_ERR "rbt_calc_ideal_load: Error getting value (active_tasks): %d\n", err);
		goto err_mattload;
	}

	check_node_id(cur_node);
	ideal_load = ideal_loads[cur_node];
	if (mattload_value <= ideal_load) {
		how_many = 0;
	} else {
		if ((mattload_value - ideal_load) >= ((p->rbt_load_diff)*load_increments[cur_node])) {
			how_many = mattload_value - ideal_load;
		} else {
			how_many = 0;
		}
	}
	*upper_bound = (load_increments[cur_node] == 0) ? 0 : how_many/load_increments[cur_node];
	check_node_id(cur_node);
	rbt_debug("Node[%d]: looping from 0 to = %d\n", cur_node, *upper_bound);
	rbt_debug("cur_active_tasks=%u, ideal_load=%u, how_many=%u, load_increments[%d]=%u\n", cur_active_tasks, ideal_load, how_many, cur_node, load_increments[cur_node]);

err_alloc_ideal_loads:
	kfree(load_increments);
err_alloc_load_increments:

	return ideal_loads;

err_mattload:
err_loadinc:
err_active_tasks:
	kfree(ideal_loads);
	ideal_loads = NULL;
	goto err_alloc_ideal_loads;
}

void rbt_policy_exec(struct work_struct *work)
{
	unsigned int *ideal_loads;
	kerrighed_node_t cur_node = kerrighed_node_id;
	kerrighed_node_t mig_node;
	krgnodemask_t online_selected_nodes;
	struct task_struct *processus;
	unsigned int j;
	int upper_bound;
	struct rbt_policy *p = container_of(work, struct rbt_policy, rbt_work.work);
	struct scheduler *s = scheduler_policy_get_scheduler(&p->policy);

	if (!s) {
		printk(KERN_ERR "rbt_policy_exec: Cannot get scheduler\n");
		return;
	}

	scheduler_get_node_set(s, &online_selected_nodes);
	scheduler_put(s);
	ideal_loads = rbt_calc_ideal_load(online_selected_nodes, &upper_bound, p);
	if (!ideal_loads) {
		printk(KERN_ERR "rbt_policy: ideal_loads = NULL.\n");
		goto out;
	}

	rcu_read_lock();
	for (j = 0; j < upper_bound; j++) {
		processus = rbt_find_a_task(&p->policy);
		if (processus != NULL) {
			mig_node = rbt_find_a_node(&cur_node, ideal_loads, &p->policy, online_selected_nodes);
			if (mig_node != KERRIGHED_NODE_ID_NONE) {
				rbt_debug("start_migrate:{processus=%d, mig_node=%d}\n", processus, mig_node);
				__migrate_linux_threads(
					processus,
					MIGR_GLOBAL_PROCESS,
					mig_node
				);
				rbt_debug("end_migrate:{processus=%d, mig_node=%d}\n", processus, mig_node);
			}
		}
	}
	rcu_read_unlock();

	/* Rescheduling the scheduler ;) */
	schedule_delayed_work(&p->rbt_work, (p->rbt_exec_freq)*HZ);

	kfree(ideal_loads);

out:
	return;
}

struct task_struct * rbt_find_a_task(struct scheduler_policy *policy_ptr)
{
	int err;
	struct task_struct *p, *max_p;
	pid_t process;
	unsigned long total_vm, lowest_vm;
	unsigned int jiffies;
	struct rbt_policy *pol = container_of(policy_ptr, struct rbt_policy, policy);
	struct scheduler *scheduler = scheduler_policy_get_scheduler(policy_ptr);
	struct process_set *processes;

	if (!scheduler)
		goto out;

	processes = scheduler_get_process_set(scheduler);
	if (!processes)
		goto put_scheduler;

	process_set_prepare_do_each_process(processes);
	process_set_do_each_process(p, processes) {
		if (!may_migrate(p))
			continue;

		process = task_pid_knr(p);

		err = scheduler_port_get_value(
			&pol->port_process_size,
			&total_vm,
			1, &process, 1);
		if (err < 0) {
			printk(KERN_ERR "rbt_find_a_task: Error getting value (process_size): %d\n", err);
			goto err_process_size;
		}

		err = scheduler_port_get_value(
			&pol->port_process_jiffies,
			&jiffies,
			1, &process, 1);
		if (err < 0) {
			printk(KERN_ERR "rbt_find_a_task: Error getting value (process_jiffies): %d\n", err);
			goto err_process_jiffies;
		}

		if ( (lowest_vm == 0) || (total_vm < lowest_vm) ) {
			lowest_vm = total_vm;
			max_p = p;
		}
	} process_set_while_each_process(p, processes);

	process_set_cleanup_do_each_process(processes);
	process_set_put(processes);
	scheduler_put(scheduler);

exit:
	return max_p;

err_process_jiffies:
err_process_size:

put_scheduler:
	scheduler_put(scheduler);

out:
	max_p = NULL;
	goto exit;
}

kerrighed_node_t rbt_find_a_node(kerrighed_node_t *next, unsigned int *ideal_loads, struct scheduler_policy *policy_ptr, const krgnodemask_t online_selected_nodes)
{
	kerrighed_node_t selected_node = KERRIGHED_NODE_ID_NONE;
	kerrighed_node_t backup = *next;
	int err;
	unsigned int mattload_value;
	struct rbt_policy *p = container_of(policy_ptr, struct rbt_policy, policy);

	err = scheduler_port_get_remote_value(
		&p->port_mattload,
		*next,
		&mattload_value,
		1, NULL, 0);
	if (err < 0) {
		printk(KERN_ERR "rbt_find_a_node: Error getting value (mattload): %d\n", err);
		return selected_node;
	}

	check_node_id(*next);
	if (mattload_value < ideal_loads[*next]) {
		selected_node = *next;
		toggle_next_node(next, online_selected_nodes);
		check_node_id(*next);
		return selected_node;
	} else {
		check_node_id(*next);
		toggle_next_node(next, online_selected_nodes);
		check_node_id(*next);
		err = scheduler_port_get_remote_value(
			&p->port_mattload,
			*next,
			&mattload_value,
			1, NULL, 0);
		if (err < 0) {
			printk(KERN_ERR "rbt_find_a_node: Error getting value (mattload): %d\n", err);
			return selected_node;
		}
		while (*next != backup) {
			check_node_id(*next);
			if (mattload_value < ideal_loads[*next]) {
				selected_node = *next;
				toggle_next_node(next, online_selected_nodes);
				check_node_id(*next);
				return selected_node;
			} else {
				toggle_next_node(next, online_selected_nodes);
				check_node_id(*next);
			}
		}
	}

	if (selected_node == KERRIGHED_NODE_ID_NONE)
		selected_node = next_krgnode_in_ring(*next, online_selected_nodes);

	return selected_node;
}

void toggle_next_node(kerrighed_node_t *next_node, const krgnodemask_t online_selected_nodes)
{
	kerrighed_node_t next_selected_node, current_node;
	current_node = *next_node;
	next_selected_node = next_krgnode_in_ring(current_node, online_selected_nodes);
	*next_node = next_selected_node;
}

kerrighed_node_t rbt_policy_new_task_node(struct scheduler_policy *policy, struct task_struct *parent)
{
	struct scheduler *s = scheduler_policy_get_scheduler(policy);
	struct rbt_policy *p = container_of(policy, struct rbt_policy, policy);
	unsigned int *ideal_loads;
	int upper_bound;
	kerrighed_node_t node = KERRIGHED_NODE_ID_NONE;
	kerrighed_node_t cur_node = kerrighed_node_id;
	krgnodemask_t nodes;

	if (!s)
		goto out_scheduler;

	if (!p)
		goto out_policy;

	scheduler_get_node_set(s, &nodes);

	ideal_loads = rbt_calc_ideal_load(nodes, &upper_bound, p);

	if (!ideal_loads) {
		printk(KERN_ERR "rbt_policy_new_task_node: ideal_loads = NULL.\n");
		goto out;
	}

	node = rbt_find_a_node(&cur_node, ideal_loads, &p->policy, nodes);
	rbt_debug("selected new node: %d.\n", node);

	kfree(ideal_loads);

out:
out_policy:
	scheduler_put(s);
out_scheduler:
	return node;
}

void check_node_id(kerrighed_node_t node)
{
	if (node >= 0) {
		if (node < KERRIGHED_MAX_NODES) {
			if (!krgnode_online(node)) {
				printk(KERN_ERR "check_node_id: Node %d not online!\n", node);
				BUG_ON(node);
			}
		} else {
			printk(KERN_ERR "check_node_id: Invalid id: %d >= KERRIGHED_MAX_NODES\n", node);
			BUG_ON(node);
		}
	} else {
		printk(KERN_ERR "check_node_id: Invalid id: %d < 0\n", node);
		BUG_ON(node);
	}
}

struct scheduler_policy *rbt_policy_new(const char *name)
{
	struct rbt_policy *p;
	struct config_group *def_groups[6];
	int err;

	p = kmalloc(sizeof(*p), GFP_KERNEL);
	if (!p)
		goto err_rbt_policy;

	err = scheduler_port_init(&p->port_mattload, "mattload",
				  &port_mattload_type, NULL, NULL);
	if (err)
		goto err_mattload;

	err = scheduler_port_init(&p->port_active_tasks, "active_tasks",
				  &port_active_tasks_type, NULL, NULL);
	if (err)
		goto err_active_tasks;

	err = scheduler_port_init(&p->port_loadinc, "loadinc",
				  &port_loadinc_type, NULL, NULL);
	if (err)
		goto err_loadinc;

	err = scheduler_port_init(&p->port_process_jiffies, "process_jiffies",
				  &port_process_jiffies_type, NULL, NULL);
	if (err)
		goto err_process_jiffies;

	err = scheduler_port_init(&p->port_process_size, "process_size",
				  &port_process_size_type, NULL, NULL);
	if (err)
		goto err_process_size;

	/* initialize default memory groups. */
	def_groups[0] = scheduler_port_config_group(&p->port_mattload);
	def_groups[1] = scheduler_port_config_group(&p->port_active_tasks);
	def_groups[2] = scheduler_port_config_group(&p->port_loadinc);
	def_groups[3] = scheduler_port_config_group(&p->port_process_jiffies);
	def_groups[4] = scheduler_port_config_group(&p->port_process_size);
	def_groups[5] = NULL;

	err = scheduler_policy_init(&p->policy, name, &rbt_policy_type,
				    def_groups);
	if (err)
		goto err_policy;

	/* Set default values */
	p->rbt_exec_freq = 5;
	p->rbt_load_diff = num_online_cpus() + 1;

	/* Initialize work */
	INIT_DELAYED_WORK(&p->rbt_work, rbt_policy_exec);

	/* Delay work for a few (two) seconds */
	printk(KERN_INFO "rbt_policy: rbt_work scheduled in %lu sec.\n", p->rbt_exec_freq);
	schedule_delayed_work(&p->rbt_work, (p->rbt_exec_freq)*HZ);

	return &p->policy;

err_policy:
	scheduler_port_cleanup(&p->port_process_size);
err_process_size:
	scheduler_port_cleanup(&p->port_process_jiffies);
err_process_jiffies:
	scheduler_port_cleanup(&p->port_loadinc);
err_loadinc:
	scheduler_port_cleanup(&p->port_active_tasks);
err_active_tasks:
	scheduler_port_cleanup(&p->port_mattload);
err_mattload:
	kfree(p);
err_rbt_policy:
	printk(KERN_ERR "error: rbt_policy creation failed!\n");
	return NULL;
}

void rbt_policy_destroy(struct scheduler_policy *policy)
{
	struct rbt_policy *p =
		container_of(policy, struct rbt_policy, policy);

	/* Flush then remove delayed works */
	cancel_rearming_delayed_work(&p->rbt_work);

	/* Clean memory */
	scheduler_policy_cleanup(policy);
	scheduler_port_cleanup(&p->port_mattload);
	scheduler_port_cleanup(&p->port_active_tasks);
	scheduler_port_cleanup(&p->port_loadinc);
	scheduler_port_cleanup(&p->port_process_jiffies);
	scheduler_port_cleanup(&p->port_process_size);
	kfree(p);
}

int __init rbt_policy_init(void)
{
	int err;

	err = scheduler_port_type_init(&port_mattload_type, NULL);
	if (err)
		goto err_mattload;
	err = scheduler_port_type_init(&port_active_tasks_type, NULL);
	if (err)
		goto err_active_tasks;
	err = scheduler_port_type_init(&port_loadinc_type, NULL);
	if (err)
		goto err_loadinc;
	err = scheduler_port_type_init(&port_process_jiffies_type, NULL);
	if (err)
		goto err_process_jiffies;
	err = scheduler_port_type_init(&port_process_size_type, NULL);
	if (err)
		goto err_process_size;
	err = scheduler_policy_type_register(&rbt_policy_type);
	if (err)
		goto err_register;

 out:
	return err;

 err_register:
	scheduler_port_type_cleanup(&port_process_size_type);
 err_process_size:
	scheduler_port_type_cleanup(&port_process_jiffies_type);
 err_process_jiffies:
	scheduler_port_type_cleanup(&port_loadinc_type);
 err_loadinc:
	scheduler_port_type_cleanup(&port_active_tasks_type);
 err_active_tasks:
	scheduler_port_type_cleanup(&port_mattload_type);
 err_mattload:
	goto out;
}

void __exit rbt_policy_exit(void)
{
	scheduler_policy_type_unregister(&rbt_policy_type);
	scheduler_port_type_cleanup(&port_process_size_type);
	scheduler_port_type_cleanup(&port_process_jiffies_type);
	scheduler_port_type_cleanup(&port_loadinc_type);
	scheduler_port_type_cleanup(&port_active_tasks_type);
	scheduler_port_type_cleanup(&port_mattload_type);
}

module_init(rbt_policy_init);
module_exit(rbt_policy_exit);
