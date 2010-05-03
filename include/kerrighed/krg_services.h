#ifndef __KRG_SERVICES__
#define __KRG_SERVICES__

#include <linux/ioctl.h>
#include <kerrighed/types.h>
#include <kerrighed/krgnodemask.h>

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                 MACROS                                   *
 *                                                                          *
 *--------------------------------------------------------------------------*/

#define KERRIGHED_PROC_MAGIC 0xD1

#define TOOLS_PROC_BASE 0
#define COMM_PROC_BASE 32
#define KERMM_PROC_BASE 96
#define KERPROC_PROC_BASE 128
#define EPM_PROC_BASE 192
#define IPC_PROC_BASE 224

/*
 * Tools related Kerrighed syscalls
 */

#define KSYS_SET_CAP          _IOW(KERRIGHED_PROC_MAGIC, \
                                   TOOLS_PROC_BASE + 0, \
                                   krg_cap_t )

#define KSYS_GET_CAP          _IOR(KERRIGHED_PROC_MAGIC, \
                                   TOOLS_PROC_BASE + 1, \
                                   krg_cap_t )

#define KSYS_SET_PID_CAP      _IOW(KERRIGHED_PROC_MAGIC, \
                                   TOOLS_PROC_BASE + 2, \
                                   krg_cap_pid_t )

#define KSYS_GET_PID_CAP      _IOR(KERRIGHED_PROC_MAGIC, \
                                   TOOLS_PROC_BASE + 3, \
                                   krg_cap_pid_t )

#define KSYS_SET_FATHER_CAP   _IOW(KERRIGHED_PROC_MAGIC, \
                                   TOOLS_PROC_BASE + 4, \
                                   krg_cap_t )

#define KSYS_GET_FATHER_CAP   _IOR(KERRIGHED_PROC_MAGIC, \
                                   TOOLS_PROC_BASE + 5, \
                                   krg_cap_t )

#define KSYS_NB_MAX_NODES     _IOR(KERRIGHED_PROC_MAGIC, \
                                   TOOLS_PROC_BASE + 6,  \
				   int)
#define KSYS_NB_MAX_CLUSTERS  _IOR(KERRIGHED_PROC_MAGIC, \
                                   TOOLS_PROC_BASE + 7,  \
				   int)

#define KSYS_GET_SUPPORTED_CAP	_IOR(KERRIGHED_PROC_MAGIC, \
				     TOOLS_PROC_BASE + 8, \
				     int)

/*
 * Communications related Kerrighed syscalls
 */

#define KSYS_GET_NODE_ID       _IOR(KERRIGHED_PROC_MAGIC, \
				    COMM_PROC_BASE + 0, \
                                    int)
#define KSYS_GET_NODES_COUNT   _IOR(KERRIGHED_PROC_MAGIC, \
				    COMM_PROC_BASE + 1,   \
                                    int)
/* Removed: #define KSYS_HOTPLUG_START     _IOW(KERRIGHED_PROC_MAGIC, \ */
/*                                              COMM_PROC_BASE + 3,   \ */
/*                                              __krgnodemask_t) */
#define KSYS_HOTPLUG_RESTART   _IOW(KERRIGHED_PROC_MAGIC, \
                                    COMM_PROC_BASE + 4,   \
                                    __krgnodemask_t)
#define KSYS_HOTPLUG_SHUTDOWN  _IOW(KERRIGHED_PROC_MAGIC, \
                                    COMM_PROC_BASE + 5,   \
                                    __krgnodemask_t)
#define KSYS_HOTPLUG_REBOOT    _IOW(KERRIGHED_PROC_MAGIC, \
                                    COMM_PROC_BASE + 6,   \
                                    __krgnodemask_t)
#define KSYS_HOTPLUG_STATUS    _IOR(KERRIGHED_PROC_MAGIC, \
                                    COMM_PROC_BASE + 7,   \
				    struct hotplug_clusters)
#define KSYS_HOTPLUG_ADD       _IOW(KERRIGHED_PROC_MAGIC, \
                                    COMM_PROC_BASE + 8,   \
                                    struct __hotplug_node_set)
#define KSYS_HOTPLUG_REMOVE    _IOW(KERRIGHED_PROC_MAGIC, \
                                    COMM_PROC_BASE + 9,   \
                                    struct __hotplug_node_set)
#define KSYS_HOTPLUG_FAIL      _IOW(KERRIGHED_PROC_MAGIC, \
                                    COMM_PROC_BASE + 10,   \
                                    struct __hotplug_node_set)
#define KSYS_HOTPLUG_NODES     _IOWR(KERRIGHED_PROC_MAGIC, \
                                     COMM_PROC_BASE + 11,  \
				     struct hotplug_nodes)
#define KSYS_HOTPLUG_POWEROFF  _IOW(KERRIGHED_PROC_MAGIC, \
                                    COMM_PROC_BASE + 12,  \
				    struct __hotplug_node_set)
/* Removed: #define KSYS_HOTPLUG_WAIT_FOR_START _IO(KERRIGHED_PROC_MAGIC, \ */
/*                                                  COMM_PROC_BASE + 13) */
#define KSYS_HOTPLUG_SET_CREATOR	_IO(KERRIGHED_PROC_MAGIC, \
					    COMM_PROC_BASE + 14)
#define KSYS_HOTPLUG_READY		_IO(KERRIGHED_PROC_MAGIC, \
					    COMM_PROC_BASE + 15)


/*
 *  Memory related Kerrighed syscalls
 */

#define KSYS_CHANGE_MAP_LOCAL_VALUE  _IOW(KERRIGHED_PROC_MAGIC, \
			                  KERMM_PROC_BASE + 0, \
					   struct kermm_new_local_data)

/*
 * Enhanced Process Management related kerrighed syscalls
 */

#define KSYS_PROCESS_MIGRATION         _IOW(KERRIGHED_PROC_MAGIC, \
                                            EPM_PROC_BASE + 0, \
                                            migration_infos_t)
#define KSYS_THREAD_MIGRATION	       _IOW(KERRIGHED_PROC_MAGIC, \
                                            EPM_PROC_BASE + 1,\
                                            migration_infos_t)
#define KSYS_APP_FREEZE                _IOW(KERRIGHED_PROC_MAGIC, \
                                            EPM_PROC_BASE + 2, \
                                            struct checkpoint_info)
#define KSYS_APP_UNFREEZE              _IOW(KERRIGHED_PROC_MAGIC, \
                                            EPM_PROC_BASE + 3, \
                                            struct checkpoint_info)
#define KSYS_APP_CHKPT                 _IOW(KERRIGHED_PROC_MAGIC, \
                                            EPM_PROC_BASE + 4, \
                                            struct checkpoint_info)
#define KSYS_APP_RESTART               _IOW(KERRIGHED_PROC_MAGIC, \
                                            EPM_PROC_BASE + 5, \
                                            struct restart_request)
#define KSYS_APP_SET_USERDATA          _IOW(KERRIGHED_PROC_MAGIC, \
                                            EPM_PROC_BASE + 6, \
                                            __u64)
#define KSYS_APP_GET_USERDATA          _IOW(KERRIGHED_PROC_MAGIC, \
                                            EPM_PROC_BASE + 7, \
                                            struct app_userdata_request)
#define KSYS_APP_CR_DISABLE		_IO(KERRIGHED_PROC_MAGIC, \
					   EPM_PROC_BASE + 8)
#define KSYS_APP_CR_ENABLE		_IO(KERRIGHED_PROC_MAGIC, \
					   EPM_PROC_BASE + 9)
#define KSYS_APP_CR_EXCLUDE		_IOW(KERRIGHED_PROC_MAGIC,	\
					     EPM_PROC_BASE + 10,	\
					     struct cr_mm_region)


/*
 * IPC related kerrighed syscalls
 */
#define KSYS_IPC_MSGQ_CHKPT            _IOW(KERRIGHED_PROC_MAGIC,       \
					    IPC_PROC_BASE + 0,		\
					    int[2])
#define KSYS_IPC_MSGQ_RESTART          _IOW(KERRIGHED_PROC_MAGIC, \
					    IPC_PROC_BASE + 1,	  \
					    int)
#define KSYS_IPC_SEM_CHKPT             _IOW(KERRIGHED_PROC_MAGIC,       \
					    IPC_PROC_BASE + 2,		\
					    int[2])
#define KSYS_IPC_SEM_RESTART           _IOW(KERRIGHED_PROC_MAGIC, \
					    IPC_PROC_BASE + 3,	  \
					    int)
#define KSYS_IPC_SHM_CHKPT             _IOW(KERRIGHED_PROC_MAGIC,       \
					    IPC_PROC_BASE + 4,		\
					    int[2])
#define KSYS_IPC_SHM_RESTART           _IOW(KERRIGHED_PROC_MAGIC, \
					    IPC_PROC_BASE + 5,	  \
					    int)

/*
 * HotPlug
 */

struct hotplug_nodes {
	char *nodes;
};

struct hotplug_clusters {
	char clusters[KERRIGHED_MAX_CLUSTERS];
};

/* __hotplug_node_set is the ioctl parameter (sized by KERRIGHED_HARD_MAX_NODES)
   hotplug_node_set is the structure actually used by kernel (size by KERRIGHED_MAX_NODES)
*/
struct __hotplug_node_set {
	int subclusterid;
	__krgnodemask_t v;
};


/*
 * Ctnr
 */
typedef struct kermm_new_local_data {
	unsigned long data_place;
} kermm_new_local_data_t;

#endif
