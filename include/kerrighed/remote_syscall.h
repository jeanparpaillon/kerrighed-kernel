#ifndef __REMOTE_SYSCALL_H__
#define __REMOTE_SYSCALL_H__

#include <linux/types.h>

struct rpc_desc;
struct pid;
struct cred;

struct rpc_desc *krg_remote_syscall_begin(int req, pid_t pid,
					  const void *msg, size_t size);
void __krg_remote_syscall_end(struct rpc_desc *desc);
void __krg_remote_syscall_unlock(pid_t pid);
void krg_remote_syscall_end(struct rpc_desc *desc, pid_t pid);
int krg_remote_syscall_simple(int req, pid_t pid, const void *msg, size_t size);

struct pid *krg_handle_remote_syscall_begin(struct rpc_desc *desc,
					    const void *_msg, size_t size,
					    void *msg,
					    const struct cred **old_cred);
void krg_handle_remote_syscall_end(struct pid *pid,
				   const struct cred *old_cred);

void remote_signals_init(void);
void remote_sched_init(void);
void remote_sys_init(void);

#endif /* __REMOTE_SYSCALL_H__ */
