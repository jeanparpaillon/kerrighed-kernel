#ifndef __KKRG_SEM__
#define __KKRG_SEM__

#define sc_semmni       sem_ctls[3]

int krg_ipc_sem_newary(struct ipc_namespace *ns, struct sem_array *sma);

void krg_ipc_sem_freeary(struct ipc_namespace *ns,
			 struct kern_ipc_perm *ipcp);

void krg_ipc_sem_wakeup_process(struct sem_queue *q, int error);

int krg_ipc_sem_copy_semundo(unsigned long clone_flags,
			     struct task_struct *tsk);

struct sem_undo *krg_ipc_sem_find_undo(struct sem_array* sma);

void krg_ipc_sem_exit_sem(struct task_struct * tsk);

int newary(struct ipc_namespace *ns, struct ipc_params *params);

struct sem_array *sem_lock(struct ipc_namespace *ns, int id);

struct sem_array *sem_lock_check(struct ipc_namespace *ns, int id);

static inline struct sem_array *local_sem_lock(struct ipc_namespace *ns, int id)
{
	struct kern_ipc_perm *ipcp = local_ipc_lock(&sem_ids(ns), id);

	if (IS_ERR(ipcp))
		return (struct sem_array *)ipcp;

	return container_of(ipcp, struct sem_array, sem_perm);
}

static inline void sem_unlock(struct sem_array *sma)
{
	ipc_unlock(&(sma)->sem_perm);
}

static inline void local_sem_unlock(struct sem_array *sma)
{
	local_ipc_unlock(&(sma)->sem_perm);
}

/* caller is responsible to call kfree(q->undo) before if needed */
static inline void free_semqueue(struct sem_queue *q)
{
	if (q->sops)
		kfree(q->sops);
	kfree(q);
}

void local_freeary(struct ipc_namespace *ns, struct kern_ipc_perm *ipcp);

void __exit_sem_found(struct sem_array *sma, struct sem_undo *un);

#endif
