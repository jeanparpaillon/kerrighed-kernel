#ifndef __KKRG_MSG__
#define __KKRG_MSG__

/** Kerrighed Hooks **/

extern int (*kh_ipc_msg_newque)(struct ipc_namespace *ns,
				struct msg_queue *msq);

extern void (*kh_ipc_msg_freeque)(struct ipc_namespace *ns,
				  struct kern_ipc_perm *ipcp);

extern long (*kh_ipc_msgsnd)(int msqid, long mtype, void __user *mtext,
			     size_t msgsz, int msgflg, struct ipc_namespace *ns,
			     pid_t tgid);

extern long (*kh_ipc_msgrcv)(int msqid, long *pmtype, void __user *mtext,
			     size_t msgsz, long msgtyp, int msgflg,
			     struct ipc_namespace *ns, pid_t tgid);

static inline struct msg_queue *local_msg_lock(struct ipc_namespace *ns, int id)
{
	struct kern_ipc_perm *ipcp = local_ipc_lock(&msg_ids(ns), id);

	if (IS_ERR(ipcp))
		return (struct msg_queue *)ipcp;

	return container_of(ipcp, struct msg_queue, q_perm);
}

static inline void local_msg_unlock(struct msg_queue *msq)
{
	local_ipc_unlock(&(msq)->q_perm);
}

long __do_msgsnd(int msqid, long mtype, void __user *mtext,
		 size_t msgsz, int msgflg, struct ipc_namespace *ns,
		 pid_t tgid);

long __do_msgrcv(int msqid, long *pmtype, void __user *mtext,
		 size_t msgsz, long msgtyp, int msgflg,
		 struct ipc_namespace *ns, pid_t tgid);

void local_master_freeque(struct ipc_namespace *ns, struct kern_ipc_perm *ipcp);

#endif // __KKRG_MSG__
