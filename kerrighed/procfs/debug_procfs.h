#ifndef DEBUG_PROCFS_H

#define DEBUG_PROCFS_H

/**
 * Enable debug for the whole module
 **/
/* #define PROCFS */

#ifdef PROCFS

/**
 * Enable debug by file
 **/
#define FILE_CLUSTER_INFO
#define FILE_STATIC_NODE_INFO
#define FILE_STATIC_CPU_INFO
#define FILE_DYNAMIC_NODE_INFO
#define FILE_DYNAMIC_CPU_INFO
#define FILE_PROC_PID_INFO
//#define FILE_PROC_INFO_FILE
//#define FILE_KRG_PROCFS

/**
 * Define Debug topics
 **/
#define DEBUG_PROC_PID_FILES    (1<<1)
#define DEBUG_KRG_PROCFS        (1<<9)

/**
 * Select which topic to debug
 **/

/* #define DEBUG_MASQ (DEBUG_ALL) */
#define DEBUG_MASQ (DEBUG_PROC_PID_FILES)

/**
 * Select the debug noise global level
 **/
#define DEBUG_LEVEL_GLOBAL 5

#endif
#endif
