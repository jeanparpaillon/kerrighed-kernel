#ifndef __EPM_NETWORK_GHOST_H__
#define __EPM_NETWORK_GHOST_H__

struct rpc_desc;
struct task_struct;
struct pt_regs;
struct epm_action;

pid_t send_task(struct rpc_desc *desc,
		struct task_struct *tsk,
		struct pt_regs *task_regs,
		struct epm_action *action);
struct task_struct *recv_task(struct rpc_desc *desc, struct epm_action *action);

#endif /* __EPM_NETWORK_GHOST_H__ */
