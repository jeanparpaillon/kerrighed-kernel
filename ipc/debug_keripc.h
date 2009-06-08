#ifndef __DEBUG_KERIPC_H__

#define __DEBUG_KERIPC_H__

#include <kerrighed/pid.h>
#include <kerrighed/debug.h>
#include <kerrighed/debug_tools2.h>

#define DBG_KERIPC_INITS        "init"
#define DBG_KERIPC_IPC_MAP      "ipc_map"
#define DBG_KERIPC_SHM_MAP      "shm_map"
#define DBG_KERIPC_SHM_NEWSEG   "shm_newseg"
#define DBG_KERIPC_SHM_LOCK     "shm_lock"
#define DBG_KERIPC_SHMID_LINKER "shm_id_linker"
#define DBG_KERIPC_PAGE_FAULTS  "page_faults"
#define DBG_KERIPC_MOBILITY	"mobility"
#define DBG_KERIPC_MSG          "msg"
#define DBG_KERIPC_MSG_LINKER   "msg_linker"
#define DBG_KERIPC_MSG_LOCK     "msg_lock"
#define DBG_KERIPC_SEM          "sem"
#define DBG_KERIPC_SEMARRAY_LINKER   "sem_array_linker"
#define DBG_KERIPC_SEMUNDO_LINKER   "sem_undo_linker"
#define DBG_KERIPC_SEM_LOCK     "sem_lock"

static inline struct dentry * init_ipc_debug(void)
{
#ifndef CONFIG_KRG_DEBUG
	return NULL;
#else
	struct dentry *d = debug_define("ipc", 0);
	DEBUG_MASK("ipc", DBG_KERIPC_INITS);
	DEBUG_MASK("ipc", DBG_KERIPC_IPC_MAP);
	DEBUG_MASK("ipc", DBG_KERIPC_SHM_MAP);
	DEBUG_MASK("ipc", DBG_KERIPC_SHM_NEWSEG);
	DEBUG_MASK("ipc", DBG_KERIPC_SHM_LOCK);
	DEBUG_MASK("ipc", DBG_KERIPC_SHMID_LINKER);
	DEBUG_MASK("ipc", DBG_KERIPC_PAGE_FAULTS);
	DEBUG_MASK("ipc", DBG_KERIPC_MOBILITY);

	DEBUG_MASK("ipc", DBG_KERIPC_MSG);
	DEBUG_MASK("ipc", DBG_KERIPC_MSG_LINKER);
	DEBUG_MASK("ipc", DBG_KERIPC_MSG_LOCK);

	DEBUG_MASK("ipc", DBG_KERIPC_SEM);
	DEBUG_MASK("ipc", DBG_KERIPC_SEMARRAY_LINKER);
	DEBUG_MASK("ipc", DBG_KERIPC_SEMUNDO_LINKER);
	DEBUG_MASK("ipc", DBG_KERIPC_SEM_LOCK);
	return d;
#endif
}

#ifdef DEBUG
#undef DEBUG
#endif

#ifndef CONFIG_KRG_DEBUG
#	define IPCDEBUG(mask, level, format, args...) do {} while(0)
#else
#	define IPCDEBUG(mask, level, format, args...)			\
	if (match_debug("ipc", mask, level)) {				\
		printk (KERN_DEBUG DEBUG_NORMAL				\
			"%s - (%s) - %d : ", MODULE_NAME, __PRETTY_FUNCTION__, \
			task_pid_knr(current)) ;					\
		printk (format, ## args) ;				\
	}
#endif

#endif // __DEBUG_KERIPC_H__
