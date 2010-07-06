#ifndef _LINUX_THREADS_H
#define _LINUX_THREADS_H


/*
 * The default limit for the nr of threads is now in
 * /proc/sys/kernel/threads-max.
 */

/*
 * Maximum supported processors.  Setting this smaller saves quite a
 * bit of memory.  Use nr_cpu_ids instead of this except for static bitmaps.
 */
#ifndef CONFIG_NR_CPUS
/* FIXME: This should be fixed in the arch's Kconfig */
#define CONFIG_NR_CPUS	1
#endif

/* Places which use this should consider cpumask_var_t. */
#define NR_CPUS		CONFIG_NR_CPUS

#define MIN_THREADS_LEFT_FOR_ROOT 4

#ifndef CONFIG_KRG_PROC
/*
 * This controls the default maximum pid allocated to a process
 */
#define PID_MAX_DEFAULT (CONFIG_BASE_SMALL ? 0x1000 : 0x8000)

/*
 * A maximum of 4 million PIDs should be enough for a while.
 * [NOTE: PID/TIDs are limited to 2^29 ~= 500+ million, see futex.h.]
 */
#define PID_MAX_LIMIT (CONFIG_BASE_SMALL ? PAGE_SIZE * 8 : \
	(sizeof(long) > 4 ? 4 * 1024 * 1024 : PID_MAX_DEFAULT))

#else /* CONFIG_KRG_PROC */

#include <kerrighed/sys/types.h>

/* We need the number of bits for Kerrighed PIDs definitions. */
#define NR_BITS_PID_MAX_DEFAULT (CONFIG_BASE_SMALL ? 12 : 15)
#define PID_MAX_DEFAULT (1 << NR_BITS_PID_MAX_DEFAULT)

/*
 * Maximise number of PID bits:
 * - 30 bits are the limitation of FUTEX_TID_MASK in futex.h,
 * - 1 bit for GLOBAL_PID_MASK
 * - node bits are defined in include/kerrighed/sys/types.h
 */
#define NR_BITS_PID_MAX_LIMIT (CONFIG_BASE_SMALL ? PAGE_SHIFT + 3 : \
	(sizeof(long) > 4 ? (29 - NR_BITS_IN_MAX_NODE_ID) : \
	NR_BITS_PID_MAX_DEFAULT))
#define PID_MAX_LIMIT (1 << NR_BITS_PID_MAX_LIMIT)

#endif /* CONFIG_KRG_PROC */

#endif
