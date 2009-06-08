#ifndef __KRG_CPU_PROBE_H__
#define __KRG_CPU_PROBE_H__

#define CPU_PROBE_NAME "cpu_probe"

typedef struct cpu_probe_data {
	clock_t cpu_used;
	clock_t cpu_total;
} cpu_probe_data_t;

#endif /* __KRG_CPU_PROBE_H__ */
