#ifndef __KKRG_CPU_ID_H__
#define __KKRG_CPU_ID_H__

#include <linux/threads.h>
#include <kerrighed/sys/types.h>
#include <kerrighed/krginit.h>

static inline int __krg_cpu_id(kerrighed_node_t node, int cpu_id)
{
	return node * NR_CPUS + cpu_id;
}

static inline int krg_cpu_id(int local_cpu_id)
{
	return __krg_cpu_id(kerrighed_node_id, local_cpu_id);
}

static inline int krg_cpu_is_local(int krg_cpu_id)
{
	int min_local_cpu = kerrighed_node_id * NR_CPUS;

	return krg_cpu_id >= min_local_cpu
		&& krg_cpu_id < min_local_cpu + NR_CPUS;
}

static inline kerrighed_node_t krg_cpu_node(int krg_cpu_id)
{
	return krg_cpu_id / NR_CPUS;
}

static inline int local_cpu_id(int krg_cpu_id)
{
	return krg_cpu_id % NR_CPUS;
}

#endif /* __KKRG_CPU_ID_H__ */
