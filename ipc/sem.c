/*
 * linux/ipc/sem.c
 * Copyright (C) 1992 Krishna Balasubramanian
 * Copyright (C) 1995 Eric Schenk, Bruno Haible
 *
 * IMPLEMENTATION NOTES ON CODE REWRITE (Eric Schenk, January 1995):
 * This code underwent a massive rewrite in order to solve some problems
 * with the original code. In particular the original code failed to
 * wake up processes that were waiting for semval to go to 0 if the
 * value went to 0 and was then incremented rapidly enough. In solving
 * this problem I have also modified the implementation so that it
 * processes pending operations in a FIFO manner, thus give a guarantee
 * that processes waiting for a lock on the semaphore won't starve
 * unless another locking process fails to unlock.
 * In addition the following two changes in behavior have been introduced:
 * - The original implementation of semop returned the value
 *   last semaphore element examined on success. This does not
 *   match the manual page specifications, and effectively
 *   allows the user to read the semaphore even if they do not
 *   have read permissions. The implementation now returns 0
 *   on success as stated in the manual page.
 * - There is some confusion over whether the set of undo adjustments
 *   to be performed at exit should be done in an atomic manner.
 *   That is, if we are attempting to decrement the semval should we queue
 *   up and wait until we can do so legally?
 *   The original implementation attempted to do this.
 *   The current implementation does not do so. This is because I don't
 *   think it is the right thing (TM) to do, and because I couldn't
 *   see a clean way to get the old behavior with the new design.
 *   The POSIX standard and SVID should be consulted to determine
 *   what behavior is mandated.
 *
 * Further notes on refinement (Christoph Rohland, December 1998):
 * - The POSIX standard says, that the undo adjustments simply should
 *   redo. So the current implementation is o.K.
 * - The previous code had two flaws:
 *   1) It actively gave the semaphore to the next waiting process
 *      sleeping on the semaphore. Since this process did not have the
 *      cpu this led to many unnecessary context switches and bad
 *      performance. Now we only check which process should be able to
 *      get the semaphore and if this process wants to reduce some
 *      semaphore value we simply wake it up without doing the
 *      operation. So it has to try to get it later. Thus e.g. the
 *      running process may reacquire the semaphore during the current
 *      time slice. If it only waits for zero or increases the semaphore,
 *      we do the operation in advance and wake it up.
 *   2) It did not wake up all zero waiting processes. We try to do
 *      better but only get the semops right which only wait for zero or
 *      increase. If there are decrement operations in the operations
 *      array we do the same as before.
 *
 * With the incarnation of O(1) scheduler, it becomes unnecessary to perform
 * check/retry algorithm for waking up blocked processes as the new scheduler
 * is better at handling thread switch than the old one.
 *
 * /proc/sysvipc/sem support (c) 1999 Dragos Acostachioaie <dragos@iname.com>
 *
 * SMP-threaded, sysctl's added
 * (c) 1999 Manfred Spraul <manfred@colorfullife.com>
 * Enforced range limit on SEM_UNDO
 * (c) 2001 Red Hat Inc
 * Lockless wakeup
 * (c) 2003 Manfred Spraul <manfred@colorfullife.com>
 *
 * support for audit of ipc object properties and permission changes
 * Dustin Kirkland <dustin.kirkland@us.ibm.com>
 *
 * namespaces support
 * OpenVZ, SWsoft Inc.
 * Pavel Emelianov <xemul@openvz.org>
 */

#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/time.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/seq_file.h>
#include <linux/rwsem.h>
#include <linux/nsproxy.h>
#include <linux/ipc_namespace.h>

#include <asm/uaccess.h>
#include "util.h"
#ifdef CONFIG_KRG_IPC
#include <linux/random.h>
#include <kerrighed/pid.h>
#include "krgsem.h"
#endif

#ifdef CONFIG_KRG_IPC
#define assert_mutex_locked(x) BUG_ON(!mutex_is_locked(x))
#endif

#define sem_ids(ns)	((ns)->ids[IPC_SEM_IDS])

#ifndef CONFIG_KRG_IPC
#define sem_unlock(sma)		ipc_unlock(&(sma)->sem_perm)
#endif
#define sem_checkid(sma, semid)	ipc_checkid(&sma->sem_perm, semid)

#ifndef CONFIG_KRG_IPC
static int newary(struct ipc_namespace *, struct ipc_params *);
#endif
static void freeary(struct ipc_namespace *, struct kern_ipc_perm *);
#ifdef CONFIG_PROC_FS
static int sysvipc_sem_proc_show(struct seq_file *s, void *it);
#endif

#define SEMMSL_FAST	256 /* 512 bytes on stack */
#define SEMOPM_FAST	64  /* ~ 372 bytes on stack */

/*
 * linked list protection:
 *	sem_undo.id_next,
 *	sem_array.sem_pending{,last},
 *	sem_array.sem_undo: sem_lock() for read/write
 *	sem_undo.proc_next: only "current" is allowed to read/write that field.
 *	
 */

#define sc_semmsl	sem_ctls[0]
#define sc_semmns	sem_ctls[1]
#define sc_semopm	sem_ctls[2]
#define sc_semmni	sem_ctls[3]

void sem_init_ns(struct ipc_namespace *ns)
{
	ns->sc_semmsl = SEMMSL;
	ns->sc_semmns = SEMMNS;
	ns->sc_semopm = SEMOPM;
	ns->sc_semmni = SEMMNI;
	ns->used_sems = 0;
	ipc_init_ids(&ns->ids[IPC_SEM_IDS]);
}

#ifdef CONFIG_IPC_NS
void sem_exit_ns(struct ipc_namespace *ns)
{
	free_ipcs(ns, &sem_ids(ns), freeary);
	idr_destroy(&ns->ids[IPC_SEM_IDS].ipcs_idr);
}
#endif

void __init sem_init (void)
{
	sem_init_ns(&init_ipc_ns);
	ipc_init_proc_interface("sysvipc/sem",
				"       key      semid perms      nsems   uid   gid  cuid  cgid      otime      ctime\n",
				IPC_SEM_IDS, sysvipc_sem_proc_show);
}

/*
 * sem_lock_(check_) routines are called in the paths where the rw_mutex
 * is not held.
 */
#ifdef CONFIG_KRG_IPC
struct sem_array *sem_lock(struct ipc_namespace *ns, int id)
#else
static inline struct sem_array *sem_lock(struct ipc_namespace *ns, int id)
#endif
{
	struct kern_ipc_perm *ipcp = ipc_lock(&sem_ids(ns), id);

	if (IS_ERR(ipcp))
		return (struct sem_array *)ipcp;

	return container_of(ipcp, struct sem_array, sem_perm);
}

static inline struct sem_array *sem_lock_check(struct ipc_namespace *ns,
						int id)
{
	struct kern_ipc_perm *ipcp = ipc_lock_check(&sem_ids(ns), id);

	if (IS_ERR(ipcp))
		return (struct sem_array *)ipcp;

	return container_of(ipcp, struct sem_array, sem_perm);
}

#ifndef CONFIG_KRG_IPC
static inline void sem_lock_and_putref(struct sem_array *sma)
{
	ipc_lock_by_ptr(&sma->sem_perm);
	ipc_rcu_putref(sma);
}

static inline void sem_getref_and_unlock(struct sem_array *sma)
{
	ipc_rcu_getref(sma);
	ipc_unlock(&(sma)->sem_perm);
}

static inline void sem_putref(struct sem_array *sma)
{
	ipc_lock_by_ptr(&sma->sem_perm);
	ipc_rcu_putref(sma);
	ipc_unlock(&(sma)->sem_perm);
}
#endif

static inline void sem_rmid(struct ipc_namespace *ns, struct sem_array *s)
{
	ipc_rmid(&sem_ids(ns), &s->sem_perm);
}

/*
 * Lockless wakeup algorithm:
 * Without the check/retry algorithm a lockless wakeup is possible:
 * - queue.status is initialized to -EINTR before blocking.
 * - wakeup is performed by
 *	* unlinking the queue entry from sma->sem_pending
 *	* setting queue.status to IN_WAKEUP
 *	  This is the notification for the blocked thread that a
 *	  result value is imminent.
 *	* call wake_up_process
 *	* set queue.status to the final value.
 * - the previously blocked thread checks queue.status:
 *   	* if it's IN_WAKEUP, then it must wait until the value changes
 *   	* if it's not -EINTR, then the operation was completed by
 *   	  update_queue. semtimedop can return queue.status without
 *   	  performing any operation on the sem array.
 *   	* otherwise it must acquire the spinlock and check what's up.
 *
 * The two-stage algorithm is necessary to protect against the following
 * races:
 * - if queue.status is set after wake_up_process, then the woken up idle
 *   thread could race forward and try (and fail) to acquire sma->lock
 *   before update_queue had a chance to set queue.status
 * - if queue.status is written before wake_up_process and if the
 *   blocked process is woken up by a signal between writing
 *   queue.status and the wake_up_process, then the woken up
 *   process could return from semtimedop and die by calling
 *   sys_exit before wake_up_process is called. Then wake_up_process
 *   will oops, because the task structure is already invalid.
 *   (yes, this happened on s390 with sysv msg).
 *
 */
#define IN_WAKEUP	1

/**
 * newary - Create a new semaphore set
 * @ns: namespace
 * @params: ptr to the structure that contains key, semflg and nsems
 *
 * Called with sem_ids.rw_mutex held (as a writer)
 */
#ifndef CONFIG_KRG_IPC
static
#endif
int newary(struct ipc_namespace *ns, struct ipc_params *params)
{
	int id;
	int retval;
	struct sem_array *sma;
	int size;
	key_t key = params->key;
	int nsems = params->u.nsems;
	int semflg = params->flg;

	if (!nsems)
		return -EINVAL;
	if (ns->used_sems + nsems > ns->sc_semmns)
		return -ENOSPC;

	size = sizeof (*sma) + nsems * sizeof (struct sem);
	sma = ipc_rcu_alloc(size);
	if (!sma) {
		return -ENOMEM;
	}
	memset (sma, 0, size);

	sma->sem_perm.mode = (semflg & S_IRWXUGO);
	sma->sem_perm.key = key;

	sma->sem_perm.security = NULL;
	retval = security_sem_alloc(sma);
	if (retval) {
		ipc_rcu_putref(sma);
		return retval;
	}

#ifdef CONFIG_KRG_IPC
	id = ipc_addid(&sem_ids(ns), &sma->sem_perm, ns->sc_semmni,
		       params->requested_id);
#else
	id = ipc_addid(&sem_ids(ns), &sma->sem_perm, ns->sc_semmni);
#endif
	if (id < 0) {
		security_sem_free(sma);
		ipc_rcu_putref(sma);
		return id;
	}
	ns->used_sems += nsems;

	sma->sem_base = (struct sem *) &sma[1];
	INIT_LIST_HEAD(&sma->sem_pending);
	INIT_LIST_HEAD(&sma->list_id);
	sma->sem_nsems = nsems;
	sma->sem_ctime = get_seconds();
#ifdef CONFIG_KRG_IPC
	INIT_LIST_HEAD(&sma->remote_sem_pending);

	if (is_krg_ipc(&sem_ids(ns))) {
		retval = krg_ipc_sem_newary(ns, sma);
		if (retval) {
			security_sem_free(sma);
			ipc_rcu_putref(sma);
			return retval;
		}
	} else

	sma->sem_perm.krgops = NULL;
#endif
	sem_unlock(sma);

	return sma->sem_perm.id;
}


/*
 * Called with sem_ids.rw_mutex and ipcp locked.
 */
static inline int sem_security(struct kern_ipc_perm *ipcp, int semflg)
{
	struct sem_array *sma;

	sma = container_of(ipcp, struct sem_array, sem_perm);
	return security_sem_associate(sma, semflg);
}

/*
 * Called with sem_ids.rw_mutex and ipcp locked.
 */
static inline int sem_more_checks(struct kern_ipc_perm *ipcp,
				struct ipc_params *params)
{
	struct sem_array *sma;

	sma = container_of(ipcp, struct sem_array, sem_perm);
	if (params->u.nsems > sma->sem_nsems)
		return -EINVAL;

	return 0;
}

SYSCALL_DEFINE3(semget, key_t, key, int, nsems, int, semflg)
{
	struct ipc_namespace *ns;
	struct ipc_ops sem_ops;
	struct ipc_params sem_params;

	ns = current->nsproxy->ipc_ns;

	if (nsems < 0 || nsems > ns->sc_semmsl)
		return -EINVAL;

	sem_ops.getnew = newary;
	sem_ops.associate = sem_security;
	sem_ops.more_checks = sem_more_checks;

	sem_params.key = key;
	sem_params.flg = semflg;
	sem_params.u.nsems = nsems;

	return ipcget(ns, &sem_ids(ns), &sem_ops, &sem_params);
}

/*
 * Determine whether a sequence of semaphore operations would succeed
 * all at once. Return 0 if yes, 1 if need to sleep, else return error code.
 */

static int try_atomic_semop (struct sem_array * sma, struct sembuf * sops,
			     int nsops, struct sem_undo *un, int pid)
{
	int result, sem_op;
	struct sembuf *sop;
	struct sem * curr;

	for (sop = sops; sop < sops + nsops; sop++) {
		curr = sma->sem_base + sop->sem_num;
		sem_op = sop->sem_op;
		result = curr->semval;
  
		if (!sem_op && result)
			goto would_block;

		result += sem_op;
		if (result < 0)
			goto would_block;
		if (result > SEMVMX)
			goto out_of_range;
		if (sop->sem_flg & SEM_UNDO) {
			int undo = un->semadj[sop->sem_num] - sem_op;
			/*
	 		 *	Exceeding the undo range is an error.
			 */
			if (undo < (-SEMAEM - 1) || undo > SEMAEM)
				goto out_of_range;
		}
		curr->semval = result;
	}

	sop--;
	while (sop >= sops) {
		sma->sem_base[sop->sem_num].sempid = pid;
		if (sop->sem_flg & SEM_UNDO)
			un->semadj[sop->sem_num] -= sop->sem_op;
		sop--;
	}
	
	sma->sem_otime = get_seconds();
	return 0;

out_of_range:
	result = -ERANGE;
	goto undo;

would_block:
	if (sop->sem_flg & IPC_NOWAIT)
		result = -EAGAIN;
	else
		result = 1;

undo:
	sop--;
	while (sop >= sops) {
		sma->sem_base[sop->sem_num].semval -= sop->sem_op;
		sop--;
	}

	return result;
}

/* Go through the pending queue for the indicated semaphore
 * looking for tasks that can be completed.
 */
static void update_queue (struct sem_array * sma)
{
	int error;
	struct sem_queue * q;

#ifdef CONFIG_KRG_IPC
	/* the following is used to ensure that a node would not
	   keep the sem for it */
	int remote = 0, loop = 0;
	if (sma->sem_perm.krgops) {
		remote = get_random_int()%2;
		loop = 1;
	}
begin:
	if (remote)
		q = list_entry(sma->remote_sem_pending.next, struct sem_queue, list);
	else
#endif

	q = list_entry(sma->sem_pending.next, struct sem_queue, list);
#ifdef CONFIG_KRG_IPC
	while ((!remote && &q->list != &sma->sem_pending)
	       || (remote && &q->list != &sma->remote_sem_pending)) {
#else
	while (&q->list != &sma->sem_pending) {
#endif
		error = try_atomic_semop(sma, q->sops, q->nsops,
					 q->undo, q->pid);

		/* Does q->sleeper still need to sleep? */
		if (error <= 0) {
			struct sem_queue *n;

			/*
			 * Continue scanning. The next operation
			 * that must be checked depends on the type of the
			 * completed operation:
			 * - if the operation modified the array, then
			 *   restart from the head of the queue and
			 *   check for threads that might be waiting
			 *   for semaphore values to become 0.
			 * - if the operation didn't modify the array,
			 *   then just continue.
			 * The order of list_del() and reading ->next
			 * is crucial: In the former case, the list_del()
			 * must be done first [because we might be the
			 * first entry in ->sem_pending], in the latter
			 * case the list_del() must be done last
			 * [because the list is invalid after the list_del()]
			 */
			if (q->alter) {
				list_del(&q->list);
#ifdef CONFIG_KRG_IPC
				if (remote)
					n = list_entry(sma->remote_sem_pending.next,
						       struct sem_queue, list);
				else
#endif
				n = list_entry(sma->sem_pending.next,
						struct sem_queue, list);
			} else {
				n = list_entry(q->list.next, struct sem_queue,
						list);
				list_del(&q->list);
			}

			/* wake up the waiting thread */
			q->status = IN_WAKEUP;

#ifdef CONFIG_KRG_IPC
			if (remote)
				krg_ipc_sem_wakeup_process(q, error);
			else
#endif
			wake_up_process(q->sleeper);
			/* hands-off: q will disappear immediately after
			 * writing q->status.
			 */
			smp_wmb();
			q->status = error;
			q = n;
		} else {
			q = list_entry(q->list.next, struct sem_queue, list);
		}
	}
#ifdef CONFIG_KRG_IPC
	if (loop) {
		remote = !remote;
		loop = 0;
		goto begin;
	}
#endif
}

/* The following counts are associated to each semaphore:
 *   semncnt        number of tasks waiting on semval being nonzero
 *   semzcnt        number of tasks waiting on semval being zero
 * This model assumes that a task waits on exactly one semaphore.
 * Since semaphore operations are to be performed atomically, tasks actually
 * wait on a whole sequence of semaphores simultaneously.
 * The counts we return here are a rough approximation, but still
 * warrant that semncnt+semzcnt>0 if the task is on the pending queue.
 */
static int count_semncnt (struct sem_array * sma, ushort semnum)
{
	int semncnt;
	struct sem_queue * q;

	semncnt = 0;
	list_for_each_entry(q, &sma->sem_pending, list) {
		struct sembuf * sops = q->sops;
		int nsops = q->nsops;
		int i;
		for (i = 0; i < nsops; i++)
			if (sops[i].sem_num == semnum
			    && (sops[i].sem_op < 0)
			    && !(sops[i].sem_flg & IPC_NOWAIT))
				semncnt++;
	}
#ifdef CONFIG_KRG_IPC
	list_for_each_entry(q, &sma->remote_sem_pending, list) {
		struct sembuf * sops = q->sops;
		int nsops = q->nsops;
		int i;
		for (i = 0; i < nsops; i++)
			if (sops[i].sem_num == semnum
			    && (sops[i].sem_op < 0)
			    && !(sops[i].sem_flg & IPC_NOWAIT))
				semncnt++;
	}
#endif
	return semncnt;
}

static int count_semzcnt (struct sem_array * sma, ushort semnum)
{
	int semzcnt;
	struct sem_queue * q;

	semzcnt = 0;
	list_for_each_entry(q, &sma->sem_pending, list) {
		struct sembuf * sops = q->sops;
		int nsops = q->nsops;
		int i;
		for (i = 0; i < nsops; i++)
			if (sops[i].sem_num == semnum
			    && (sops[i].sem_op == 0)
			    && !(sops[i].sem_flg & IPC_NOWAIT))
				semzcnt++;
	}
#ifdef CONFIG_KRG_IPC
	list_for_each_entry(q, &sma->remote_sem_pending, list) {
		struct sembuf * sops = q->sops;
		int nsops = q->nsops;
		int i;
		for (i = 0; i < nsops; i++)
			if (sops[i].sem_num == semnum
			    && (sops[i].sem_op == 0)
			    && !(sops[i].sem_flg & IPC_NOWAIT))
				semzcnt++;
	}
#endif
	return semzcnt;
}

static void free_un(struct rcu_head *head)
{
	struct sem_undo *un = container_of(head, struct sem_undo, rcu);
	kfree(un);
}

/* Free a semaphore set. freeary() is called with sem_ids.rw_mutex locked
 * as a writer and the spinlock for this semaphore set hold. sem_ids.rw_mutex
 * remains locked on exit.
 */
#ifdef CONFIG_KRG_IPC
static void freeary(struct ipc_namespace *ns, struct kern_ipc_perm *ipcp)
{
	if (is_krg_ipc(&sem_ids(ns)))
		krg_ipc_sem_freeary(ns, ipcp);
	else
		local_freeary(ns, ipcp);
}

void local_freeary(struct ipc_namespace *ns, struct kern_ipc_perm *ipcp)
#else
static void freeary(struct ipc_namespace *ns, struct kern_ipc_perm *ipcp)
#endif
{
	struct sem_undo *un, *tu;
	struct sem_queue *q, *tq;
	struct sem_array *sma = container_of(ipcp, struct sem_array, sem_perm);

#ifdef CONFIG_KRG_IPC
	if (is_krg_ipc(&sem_ids(ns)))
		BUG_ON(!list_empty(&sma->list_id));
#endif

	/* Free the existing undo structures for this semaphore set.  */
#ifdef CONFIG_KRG_IPC
	assert_mutex_locked(&sma->sem_perm.mutex);
#else
	assert_spin_locked(&sma->sem_perm.lock);
#endif
	list_for_each_entry_safe(un, tu, &sma->list_id, list_id) {
		list_del(&un->list_id);
		spin_lock(&un->ulp->lock);
		un->semid = -1;
		list_del_rcu(&un->list_proc);
		spin_unlock(&un->ulp->lock);
		call_rcu(&un->rcu, free_un);
	}

	/* Wake up all pending processes and let them fail with EIDRM. */
	list_for_each_entry_safe(q, tq, &sma->sem_pending, list) {
		list_del(&q->list);

		q->status = IN_WAKEUP;
		wake_up_process(q->sleeper); /* doesn't sleep */
		smp_wmb();
		q->status = -EIDRM;	/* hands-off q */
	}
#ifdef CONFIG_KRG_IPC
	list_for_each_entry_safe(q, tq, &sma->remote_sem_pending, list) {
		list_del(&q->list);

		/* __freeary is called on every nodes where the semarray exists:
		 * no need to care about remote pending processes */
		if (q->undo)
			kfree(q->undo);

		free_semqueue(q);
	}
#endif

	/* Remove the semaphore set from the IDR */
	sem_rmid(ns, sma);
#ifdef CONFIG_KRG_IPC
	local_sem_unlock(sma);
#else
	sem_unlock(sma);
#endif

	ns->used_sems -= sma->sem_nsems;
	security_sem_free(sma);
	ipc_rcu_putref(sma);
}

static unsigned long copy_semid_to_user(void __user *buf, struct semid64_ds *in, int version)
{
	switch(version) {
	case IPC_64:
		return copy_to_user(buf, in, sizeof(*in));
	case IPC_OLD:
	    {
		struct semid_ds out;

		ipc64_perm_to_ipc_perm(&in->sem_perm, &out.sem_perm);

		out.sem_otime	= in->sem_otime;
		out.sem_ctime	= in->sem_ctime;
		out.sem_nsems	= in->sem_nsems;

		return copy_to_user(buf, &out, sizeof(out));
	    }
	default:
		return -EINVAL;
	}
}

static int semctl_nolock(struct ipc_namespace *ns, int semid,
			 int cmd, int version, union semun arg)
{
	int err = -EINVAL;
	struct sem_array *sma;

	switch(cmd) {
	case IPC_INFO:
	case SEM_INFO:
	{
		struct seminfo seminfo;
		int max_id;

		err = security_sem_semctl(NULL, cmd);
		if (err)
			return err;
		
		memset(&seminfo,0,sizeof(seminfo));
		seminfo.semmni = ns->sc_semmni;
		seminfo.semmns = ns->sc_semmns;
		seminfo.semmsl = ns->sc_semmsl;
		seminfo.semopm = ns->sc_semopm;
		seminfo.semvmx = SEMVMX;
		seminfo.semmnu = SEMMNU;
		seminfo.semmap = SEMMAP;
		seminfo.semume = SEMUME;
		down_read(&sem_ids(ns).rw_mutex);
		if (cmd == SEM_INFO) {
			seminfo.semusz = sem_ids(ns).in_use;
			seminfo.semaem = ns->used_sems;
		} else {
			seminfo.semusz = SEMUSZ;
			seminfo.semaem = SEMAEM;
		}
		max_id = ipc_get_maxid(&sem_ids(ns));
		up_read(&sem_ids(ns).rw_mutex);
		if (copy_to_user (arg.__buf, &seminfo, sizeof(struct seminfo))) 
			return -EFAULT;
		return (max_id < 0) ? 0: max_id;
	}
	case IPC_STAT:
	case SEM_STAT:
	{
		struct semid64_ds tbuf;
		int id;

#ifdef CONFIG_KRG_IPC
		down_read(&sem_ids(ns).rw_mutex);
#endif
		if (cmd == SEM_STAT) {
			sma = sem_lock(ns, semid);
			if (IS_ERR(sma))
#ifdef CONFIG_KRG_IPC
			{
				up_read(&sem_ids(ns).rw_mutex);
				return PTR_ERR(sma);
			}
#else
				return PTR_ERR(sma);
#endif
			id = sma->sem_perm.id;
		} else {
			sma = sem_lock_check(ns, semid);
			if (IS_ERR(sma))
#ifdef CONFIG_KRG_IPC
			{
				up_read(&sem_ids(ns).rw_mutex);
				return PTR_ERR(sma);
			}
#else
				return PTR_ERR(sma);
#endif
			id = 0;
		}

		err = -EACCES;
		if (ipcperms (&sma->sem_perm, S_IRUGO))
			goto out_unlock;

		err = security_sem_semctl(sma, cmd);
		if (err)
			goto out_unlock;

		memset(&tbuf, 0, sizeof(tbuf));

		kernel_to_ipc64_perm(&sma->sem_perm, &tbuf.sem_perm);
		tbuf.sem_otime  = sma->sem_otime;
		tbuf.sem_ctime  = sma->sem_ctime;
		tbuf.sem_nsems  = sma->sem_nsems;
		sem_unlock(sma);
#ifdef CONFIG_KRG_IPC
		up_read(&sem_ids(ns).rw_mutex);
#endif
		if (copy_semid_to_user (arg.buf, &tbuf, version))
			return -EFAULT;
		return id;
	}
	default:
		return -EINVAL;
	}
	return err;
out_unlock:
	sem_unlock(sma);
#ifdef CONFIG_KRG_IPC
	up_read(&sem_ids(ns).rw_mutex);
#endif
	return err;
}

static int semctl_main(struct ipc_namespace *ns, int semid, int semnum,
		int cmd, int version, union semun arg)
{
	struct sem_array *sma;
	struct sem* curr;
	int err;
	ushort fast_sem_io[SEMMSL_FAST];
	ushort* sem_io = fast_sem_io;
	int nsems;

#ifdef CONFIG_KRG_IPC
	down_read(&sem_ids(ns).rw_mutex);
#endif
	sma = sem_lock_check(ns, semid);
	if (IS_ERR(sma))
#ifdef CONFIG_KRG_IPC
	{
		up_read(&sem_ids(ns).rw_mutex);
		return PTR_ERR(sma);
	}
#else
		return PTR_ERR(sma);
#endif

	nsems = sma->sem_nsems;

	err = -EACCES;
	if (ipcperms (&sma->sem_perm, (cmd==SETVAL||cmd==SETALL)?S_IWUGO:S_IRUGO))
		goto out_unlock;

	err = security_sem_semctl(sma, cmd);
	if (err)
		goto out_unlock;

	err = -EACCES;
	switch (cmd) {
	case GETALL:
	{
		ushort __user *array = arg.array;
		int i;

		if(nsems > SEMMSL_FAST) {
#ifndef CONFIG_KRG_IPC
			sem_getref_and_unlock(sma);
#endif

			sem_io = ipc_alloc(sizeof(ushort)*nsems);
			if(sem_io == NULL) {
#ifdef CONFIG_KRG_IPC
				err = -ENOMEM;
				goto out_unlock;
			}
			BUG_ON(sma->sem_perm.deleted);
#else
				sem_putref(sma);
				return -ENOMEM;
			}

			sem_lock_and_putref(sma);
			if (sma->sem_perm.deleted) {
				sem_unlock(sma);
				err = -EIDRM;
				goto out_free;
			}
#endif
		}

		for (i = 0; i < sma->sem_nsems; i++)
			sem_io[i] = sma->sem_base[i].semval;
		sem_unlock(sma);
		err = 0;
		if(copy_to_user(array, sem_io, nsems*sizeof(ushort)))
			err = -EFAULT;
		goto out_free;
	}
	case SETALL:
	{
		int i;
		struct sem_undo *un;
#ifndef CONFIG_KRG_IPC
		sem_getref_and_unlock(sma);
#endif

		if(nsems > SEMMSL_FAST) {
			sem_io = ipc_alloc(sizeof(ushort)*nsems);
			if(sem_io == NULL) {
#ifdef CONFIG_KRG_IPC
				err = -ENOMEM;
				goto out_unlock;
#else
				sem_putref(sma);
				return -ENOMEM;
#endif
			}
		}

		if (copy_from_user (sem_io, arg.array, nsems*sizeof(ushort))) {
#ifdef CONFIG_KRG_IPC
			err = -EFAULT;
			goto out_unlock;
#else
			sem_putref(sma);
			err = -EFAULT;
			goto out_free;
#endif
		}

		for (i = 0; i < nsems; i++) {
			if (sem_io[i] > SEMVMX) {
#ifdef CONFIG_KRG_IPC
				err = -ERANGE;
				goto out_unlock;
#else
				sem_putref(sma);
				err = -ERANGE;
				goto out_free;
#endif
			}
		}
#ifdef CONFIG_KRG_IPC
		BUG_ON(sma->sem_perm.deleted);
#else
		sem_lock_and_putref(sma);
		if (sma->sem_perm.deleted) {
			sem_unlock(sma);
			err = -EIDRM;
			goto out_free;
		}
#endif

		for (i = 0; i < nsems; i++)
			sma->sem_base[i].semval = sem_io[i];

#ifdef CONFIG_KRG_IPC
		assert_mutex_locked(&sma->sem_perm.mutex);
#else
		assert_spin_locked(&sma->sem_perm.lock);
#endif
		list_for_each_entry(un, &sma->list_id, list_id) {
			for (i = 0; i < nsems; i++)
				un->semadj[i] = 0;
		}
		sma->sem_ctime = get_seconds();
		/* maybe some queued-up processes were waiting for this */
		update_queue(sma);
		err = 0;
		goto out_unlock;
	}
	/* GETVAL, GETPID, GETNCTN, GETZCNT, SETVAL: fall-through */
	}
	err = -EINVAL;
	if(semnum < 0 || semnum >= nsems)
		goto out_unlock;

	curr = &sma->sem_base[semnum];

	switch (cmd) {
	case GETVAL:
		err = curr->semval;
		goto out_unlock;
	case GETPID:
		err = curr->sempid;
		goto out_unlock;
	case GETNCNT:
		err = count_semncnt(sma,semnum);
		goto out_unlock;
	case GETZCNT:
		err = count_semzcnt(sma,semnum);
		goto out_unlock;
	case SETVAL:
	{
		int val = arg.val;
		struct sem_undo *un;

		err = -ERANGE;
		if (val > SEMVMX || val < 0)
			goto out_unlock;


#ifdef CONFIG_KRG_IPC
		assert_mutex_locked(&sma->sem_perm.mutex);
#else
		assert_spin_locked(&sma->sem_perm.lock);
#endif
		list_for_each_entry(un, &sma->list_id, list_id)
			un->semadj[semnum] = 0;

		curr->semval = val;
		curr->sempid = task_tgid_vnr(current);
		sma->sem_ctime = get_seconds();
		/* maybe some queued-up processes were waiting for this */
		update_queue(sma);
		err = 0;
		goto out_unlock;
	}
	}
out_unlock:
	sem_unlock(sma);
out_free:
#ifdef CONFIG_KRG_IPC
	up_read(&sem_ids(ns).rw_mutex);
#endif
	if(sem_io != fast_sem_io)
		ipc_free(sem_io, sizeof(ushort)*nsems);
	return err;
}

static inline unsigned long
copy_semid_from_user(struct semid64_ds *out, void __user *buf, int version)
{
	switch(version) {
	case IPC_64:
		if (copy_from_user(out, buf, sizeof(*out)))
			return -EFAULT;
		return 0;
	case IPC_OLD:
	    {
		struct semid_ds tbuf_old;

		if(copy_from_user(&tbuf_old, buf, sizeof(tbuf_old)))
			return -EFAULT;

		out->sem_perm.uid	= tbuf_old.sem_perm.uid;
		out->sem_perm.gid	= tbuf_old.sem_perm.gid;
		out->sem_perm.mode	= tbuf_old.sem_perm.mode;

		return 0;
	    }
	default:
		return -EINVAL;
	}
}

/*
 * This function handles some semctl commands which require the rw_mutex
 * to be held in write mode.
 * NOTE: no locks must be held, the rw_mutex is taken inside this function.
 */
static int semctl_down(struct ipc_namespace *ns, int semid,
		       int cmd, int version, union semun arg)
{
	struct sem_array *sma;
	int err;
	struct semid64_ds semid64;
	struct kern_ipc_perm *ipcp;

	if(cmd == IPC_SET) {
		if (copy_semid_from_user(&semid64, arg.buf, version))
			return -EFAULT;
	}

	ipcp = ipcctl_pre_down(&sem_ids(ns), semid, cmd, &semid64.sem_perm, 0);
	if (IS_ERR(ipcp))
		return PTR_ERR(ipcp);

	sma = container_of(ipcp, struct sem_array, sem_perm);

	err = security_sem_semctl(sma, cmd);
	if (err)
		goto out_unlock;

	switch(cmd){
	case IPC_RMID:
		freeary(ns, ipcp);
		goto out_up;
	case IPC_SET:
		ipc_update_perm(&semid64.sem_perm, ipcp);
		sma->sem_ctime = get_seconds();
		break;
	default:
		err = -EINVAL;
	}

out_unlock:
	sem_unlock(sma);
out_up:
	up_write(&sem_ids(ns).rw_mutex);
	return err;
}

SYSCALL_DEFINE(semctl)(int semid, int semnum, int cmd, union semun arg)
{
	int err = -EINVAL;
	int version;
	struct ipc_namespace *ns;

	if (semid < 0)
		return -EINVAL;

	version = ipc_parse_version(&cmd);
	ns = current->nsproxy->ipc_ns;

	switch(cmd) {
	case IPC_INFO:
	case SEM_INFO:
	case IPC_STAT:
	case SEM_STAT:
		err = semctl_nolock(ns, semid, cmd, version, arg);
		return err;
	case GETALL:
	case GETVAL:
	case GETPID:
	case GETNCNT:
	case GETZCNT:
	case SETVAL:
	case SETALL:
		err = semctl_main(ns,semid,semnum,cmd,version,arg);
		return err;
	case IPC_RMID:
	case IPC_SET:
		err = semctl_down(ns, semid, cmd, version, arg);
		return err;
	default:
		return -EINVAL;
	}
}
#ifdef CONFIG_HAVE_SYSCALL_WRAPPERS
asmlinkage long SyS_semctl(int semid, int semnum, int cmd, union semun arg)
{
	return SYSC_semctl((int) semid, (int) semnum, (int) cmd, arg);
}
SYSCALL_ALIAS(sys_semctl, SyS_semctl);
#endif

/* If the task doesn't already have a undo_list, then allocate one
 * here.  We guarantee there is only one thread using this undo list,
 * and current is THE ONE
 *
 * If this allocation and assignment succeeds, but later
 * portions of this code fail, there is no need to free the sem_undo_list.
 * Just let it stay associated with the task, and it'll be freed later
 * at exit time.
 *
 * This can block, so callers must hold no locks.
 */
static inline int get_undo_list(struct sem_undo_list **undo_listp)
{
	struct sem_undo_list *undo_list;

	undo_list = current->sysvsem.undo_list;
	if (!undo_list) {
		undo_list = kzalloc(sizeof(*undo_list), GFP_KERNEL);
		if (undo_list == NULL)
			return -ENOMEM;
		spin_lock_init(&undo_list->lock);
		atomic_set(&undo_list->refcnt, 1);
		INIT_LIST_HEAD(&undo_list->list_proc);

		current->sysvsem.undo_list = undo_list;
	}
	*undo_listp = undo_list;
	return 0;
}

static struct sem_undo *lookup_undo(struct sem_undo_list *ulp, int semid)
{
	struct sem_undo *walk;

	list_for_each_entry_rcu(walk, &ulp->list_proc, list_proc) {
		if (walk->semid == semid)
			return walk;
	}
	return NULL;
}

/**
 * find_alloc_undo - Lookup (and if not present create) undo array
 * @ns: namespace
 * @semid: semaphore array id
 *
 * The function looks up (and if not present creates) the undo structure.
 * The size of the undo structure depends on the size of the semaphore
 * array, thus the alloc path is not that straightforward.
 * Lifetime-rules: sem_undo is rcu-protected, on success, the function
 * performs a rcu_read_lock().
 */
static struct sem_undo *find_alloc_undo(struct ipc_namespace *ns, int semid)
{
	struct sem_array *sma;
	struct sem_undo_list *ulp;
	struct sem_undo *un, *new;
	int nsems;
	int error;

	error = get_undo_list(&ulp);
	if (error)
		return ERR_PTR(error);

	rcu_read_lock();
	spin_lock(&ulp->lock);
	un = lookup_undo(ulp, semid);
	spin_unlock(&ulp->lock);
	if (likely(un!=NULL))
		goto out;
	rcu_read_unlock();

	/* no undo structure around - allocate one. */
	/* step 1: figure out the size of the semaphore array */
#ifdef CONFIG_KRG_IPC
	down_read(&sem_ids(ns).rw_mutex);
#endif
	sma = sem_lock_check(ns, semid);
	if (IS_ERR(sma))
#ifdef CONFIG_KRG_IPC
	{
		up_read(&sem_ids(ns).rw_mutex);
		return ERR_PTR(PTR_ERR(sma));
	}
#else
		return ERR_PTR(PTR_ERR(sma));
#endif

	nsems = sma->sem_nsems;

#ifndef CONFIG_KRG_IPC
	sem_getref_and_unlock(sma);
#endif

	/* step 2: allocate new undo structure */
	new = kzalloc(sizeof(struct sem_undo) + sizeof(short)*nsems, GFP_KERNEL);
	if (!new) {
#ifdef CONFIG_KRG_IPC
		sem_unlock(sma);
		up_read(&sem_ids(ns).rw_mutex);
#else
		sem_putref(sma);
#endif
		return ERR_PTR(-ENOMEM);
	}

#ifdef CONFIG_KRG_IPC
	BUG_ON(sma->sem_perm.deleted);
#else
	/* step 3: Acquire the lock on semaphore array */
	sem_lock_and_putref(sma);
	if (sma->sem_perm.deleted) {
		sem_unlock(sma);
		kfree(new);
		un = ERR_PTR(-EIDRM);
		goto out;
	}
#endif
	spin_lock(&ulp->lock);

	/*
	 * step 4: check for races: did someone else allocate the undo struct?
	 */
	un = lookup_undo(ulp, semid);
	if (un) {
		kfree(new);
		goto success;
	}
	/* step 5: initialize & link new undo structure */
	new->semadj = (short *) &new[1];
	new->ulp = ulp;
	new->semid = semid;
	assert_spin_locked(&ulp->lock);
	list_add_rcu(&new->list_proc, &ulp->list_proc);
#ifdef CONFIG_KRG_IPC
	assert_mutex_locked(&sma->sem_perm.mutex);
#else
	assert_spin_locked(&sma->sem_perm.lock);
#endif
	list_add(&new->list_id, &sma->list_id);
	un = new;

success:
	spin_unlock(&ulp->lock);
	rcu_read_lock();
	sem_unlock(sma);
#ifdef CONFIG_KRG_IPC
	up_read(&sem_ids(ns).rw_mutex);
#endif
out:
	return un;
}

SYSCALL_DEFINE4(semtimedop, int, semid, struct sembuf __user *, tsops,
		unsigned, nsops, const struct timespec __user *, timeout)
{
	int error = -EINVAL;
	struct sem_array *sma;
	struct sembuf fast_sops[SEMOPM_FAST];
	struct sembuf* sops = fast_sops, *sop;
	struct sem_undo *un;
	int undos = 0, alter = 0, max;
	struct sem_queue queue;
	unsigned long jiffies_left = 0;
	struct ipc_namespace *ns;

	ns = current->nsproxy->ipc_ns;

	if (nsops < 1 || semid < 0)
		return -EINVAL;
	if (nsops > ns->sc_semopm)
		return -E2BIG;
	if(nsops > SEMOPM_FAST) {
		sops = kmalloc(sizeof(*sops)*nsops,GFP_KERNEL);
		if(sops==NULL)
			return -ENOMEM;
	}
	if (copy_from_user (sops, tsops, nsops * sizeof(*tsops))) {
		error=-EFAULT;
		goto out_free;
	}
	if (timeout) {
		struct timespec _timeout;
		if (copy_from_user(&_timeout, timeout, sizeof(*timeout))) {
			error = -EFAULT;
			goto out_free;
		}
		if (_timeout.tv_sec < 0 || _timeout.tv_nsec < 0 ||
			_timeout.tv_nsec >= 1000000000L) {
			error = -EINVAL;
			goto out_free;
		}
		jiffies_left = timespec_to_jiffies(&_timeout);
	}
	max = 0;
	for (sop = sops; sop < sops + nsops; sop++) {
		if (sop->sem_num >= max)
			max = sop->sem_num;
		if (sop->sem_flg & SEM_UNDO)
			undos = 1;
		if (sop->sem_op != 0)
			alter = 1;
	}

#ifdef CONFIG_KRG_IPC
	if (is_krg_ipc(&sem_ids(ns)))
		un = NULL;
	else
#endif
	if (undos) {
		un = find_alloc_undo(ns, semid);
		if (IS_ERR(un)) {
			error = PTR_ERR(un);
			goto out_free;
		}
	} else
		un = NULL;

#ifdef CONFIG_KRG_IPC
	down_read(&sem_ids(ns).rw_mutex);
#endif
	sma = sem_lock_check(ns, semid);
	if (IS_ERR(sma)) {
		if (un)
			rcu_read_unlock();
		error = PTR_ERR(sma);
#ifdef CONFIG_KRG_IPC
		up_read(&sem_ids(ns).rw_mutex);
#endif
		goto out_free;
	}

	/*
	 * semid identifiers are not unique - find_alloc_undo may have
	 * allocated an undo structure, it was invalidated by an RMID
	 * and now a new array with received the same id. Check and fail.
	 * This case can be detected checking un->semid. The existance of
	 * "un" itself is guaranteed by rcu.
	 */
	error = -EIDRM;
	if (un) {
		if (un->semid == -1) {
			rcu_read_unlock();
			goto out_unlock_free;
		} else {
			/*
			 * rcu lock can be released, "un" cannot disappear:
			 * - sem_lock is acquired, thus IPC_RMID is
			 *   impossible.
			 * - exit_sem is impossible, it always operates on
			 *   current (or a dead task).
			 */

			rcu_read_unlock();
		}
	}

	error = -EFBIG;
	if (max >= sma->sem_nsems)
		goto out_unlock_free;

	error = -EACCES;
	if (ipcperms(&sma->sem_perm, alter ? S_IWUGO : S_IRUGO))
		goto out_unlock_free;

	error = security_sem_semop(sma, sops, nsops, alter);
	if (error)
		goto out_unlock_free;

#ifdef CONFIG_KRG_IPC
	if (undos && sma->sem_perm.krgops) {
		un = krg_ipc_sem_find_undo(sma);
		if (IS_ERR(un)) {
			error = PTR_ERR(un);
			goto out_unlock_free;
		}
	}
#endif

	error = try_atomic_semop (sma, sops, nsops, un, task_tgid_vnr(current));
	if (error <= 0) {
		if (alter && error == 0)
			update_queue (sma);
		goto out_unlock_free;
	}

	/* We need to sleep on this operation, so we put the current
	 * task into the pending queue and go to sleep.
	 */
		
	queue.sops = sops;
	queue.nsops = nsops;
	queue.undo = un;
	queue.pid = task_tgid_vnr(current);
	queue.alter = alter;
#ifdef CONFIG_KRG_IPC
	queue.semid = sma->sem_perm.id;
	queue.node = kerrighed_node_id;
#endif
	if (alter)
		list_add_tail(&queue.list, &sma->sem_pending);
	else
		list_add(&queue.list, &sma->sem_pending);

	queue.status = -EINTR;
	queue.sleeper = current;
	current->state = TASK_INTERRUPTIBLE;
	sem_unlock(sma);
#ifdef CONFIG_KRG_IPC
	up_read(&sem_ids(ns).rw_mutex);
#endif

	if (timeout)
		jiffies_left = schedule_timeout(jiffies_left);
	else
		schedule();

	error = queue.status;
	while(unlikely(error == IN_WAKEUP)) {
		cpu_relax();
		error = queue.status;
	}

	if (error != -EINTR) {
		/* fast path: update_queue already obtained all requested
		 * resources */
		goto out_free;
	}

#ifdef CONFIG_KRG_IPC
	down_read(&sem_ids(ns).rw_mutex);
#endif
	sma = sem_lock(ns, semid);
	if (IS_ERR(sma)) {
		error = -EIDRM;
#ifdef CONFIG_KRG_IPC
		up_read(&sem_ids(ns).rw_mutex);
#endif
		goto out_free;
	}

	/*
	 * If queue.status != -EINTR we are woken up by another process
	 */
	error = queue.status;
	if (error != -EINTR) {
		goto out_unlock_free;
	}

	/*
	 * If an interrupt occurred we have to clean up the queue
	 */
	if (timeout && jiffies_left == 0)
		error = -EAGAIN;
	list_del(&queue.list);

out_unlock_free:
	sem_unlock(sma);
#ifdef CONFIG_KRG_IPC
	up_read(&sem_ids(ns).rw_mutex);
#endif
out_free:
	if(sops != fast_sops)
		kfree(sops);
	return error;
}

SYSCALL_DEFINE3(semop, int, semid, struct sembuf __user *, tsops,
		unsigned, nsops)
{
	return sys_semtimedop(semid, tsops, nsops, NULL);
}

/* If CLONE_SYSVSEM is set, establish sharing of SEM_UNDO state between
 * parent and child tasks.
 */

#ifdef CONFIG_KRG_IPC
int __copy_semundo(unsigned long clone_flags, struct task_struct *tsk);

int copy_semundo(unsigned long clone_flags, struct task_struct *tsk)
{
	struct ipc_namespace *ns;

	ns = task_nsproxy(tsk)->ipc_ns;

	if (is_krg_ipc(&sem_ids(ns)))
		return krg_ipc_sem_copy_semundo(clone_flags, tsk);

	return __copy_semundo(clone_flags, tsk);
}

int __copy_semundo(unsigned long clone_flags, struct task_struct *tsk)
#else
int copy_semundo(unsigned long clone_flags, struct task_struct *tsk)
#endif
{
	struct sem_undo_list *undo_list;
	int error;

#ifdef CONFIG_KRG_IPC
	BUG_ON((clone_flags & CLONE_SYSVSEM)
	       && current->sysvsem.undo_list_id != UNIQUE_ID_NONE);
	tsk->sysvsem.undo_list_id = UNIQUE_ID_NONE;
#endif

	if (clone_flags & CLONE_SYSVSEM) {
		error = get_undo_list(&undo_list);
		if (error)
			return error;
		atomic_inc(&undo_list->refcnt);
		tsk->sysvsem.undo_list = undo_list;
	} else 
		tsk->sysvsem.undo_list = NULL;

	return 0;
}

void __exit_sem_found(struct sem_array *sma, struct sem_undo *un)
{
	int i;

	/* perform adjustments registered in un */
	for (i = 0; i < sma->sem_nsems; i++) {
		struct sem * semaphore = &sma->sem_base[i];
		if (un->semadj[i]) {
			semaphore->semval += un->semadj[i];
			/*
			 * Range checks of the new semaphore value,
			 * not defined by sus:
			 * - Some unices ignore the undo entirely
			 *   (e.g. HP UX 11i 11.22, Tru64 V5.1)
			 * - some cap the value (e.g. FreeBSD caps
			 *   at 0, but doesn't enforce SEMVMX)
			 *
			 * Linux caps the semaphore value, both at 0
			 * and at SEMVMX.
			 *
			 * 	Manfred <manfred@colorfullife.com>
			 */
			if (semaphore->semval < 0)
				semaphore->semval = 0;
			if (semaphore->semval > SEMVMX)
				semaphore->semval = SEMVMX;
			semaphore->sempid = task_tgid_vnr(current);
		}
	}
	sma->sem_otime = get_seconds();
	/* maybe some queued-up processes were waiting for this */
	update_queue(sma);
}


/*
 * add semadj values to semaphores, free undo structures.
 * undo structures are not freed when semaphore arrays are destroyed
 * so some of them may be out of date.
 * IMPLEMENTATION NOTE: There is some confusion over whether the
 * set of adjustments that needs to be done should be done in an atomic
 * manner or not. That is, if we are attempting to decrement the semval
 * should we queue up and wait until we can do so legally?
 * The original implementation attempted to do this (queue and wait).
 * The current implementation does not do so. The POSIX standard
 * and SVID should be consulted to determine what behavior is mandated.
 */
#ifdef CONFIG_KRG_IPC
void __exit_sem(struct task_struct *tsk)
#else
void exit_sem(struct task_struct *tsk)
#endif
{
	struct sem_undo_list *ulp;

	ulp = tsk->sysvsem.undo_list;
	if (!ulp)
		return;
	tsk->sysvsem.undo_list = NULL;

	if (!atomic_dec_and_test(&ulp->refcnt))
		return;

	for (;;) {
		struct sem_array *sma;
		struct sem_undo *un;
		int semid;

		rcu_read_lock();
		un = list_entry(rcu_dereference(ulp->list_proc.next),
					struct sem_undo, list_proc);
		if (&un->list_proc == &ulp->list_proc)
			semid = -1;
		 else
			semid = un->semid;
		rcu_read_unlock();

		if (semid == -1)
			break;

#ifdef CONFIG_KRG_IPC
		down_read(&sem_ids(tsk->nsproxy->ipc_ns).rw_mutex);
#endif
		sma = sem_lock_check(tsk->nsproxy->ipc_ns, un->semid);

		/* exit_sem raced with IPC_RMID, nothing to do */
		if (IS_ERR(sma))
#ifdef CONFIG_KRG_IPC
		{
			up_read(&sem_ids(tsk->nsproxy->ipc_ns).rw_mutex);
			continue;
		}
#else
			continue;
#endif

		un = lookup_undo(ulp, semid);
		if (un == NULL) {
			/* exit_sem raced with IPC_RMID+semget() that created
			 * exactly the same semid. Nothing to do.
			 */
#ifdef CONFIG_KRG_IPC
			up_read(&sem_ids(tsk->nsproxy->ipc_ns).rw_mutex);
#endif
			sem_unlock(sma);
			continue;
		}

		/* remove un from the linked lists */
#ifdef CONFIG_KRG_IPC
		assert_mutex_locked(&sma->sem_perm.mutex);
#else
		assert_spin_locked(&sma->sem_perm.lock);
#endif

		list_del(&un->list_id);

		spin_lock(&ulp->lock);
		list_del_rcu(&un->list_proc);
		spin_unlock(&ulp->lock);

		__exit_sem_found(sma, un);
		sem_unlock(sma);
#ifdef CONFIG_KRG_IPC
		up_read(&sem_ids(tsk->nsproxy->ipc_ns).rw_mutex);
#endif
		call_rcu(&un->rcu, free_un);
	}
	kfree(ulp);
}

#ifdef CONFIG_KRG_IPC
void exit_sem(struct task_struct *tsk)
{
	struct ipc_namespace *ns;

	ns = task_nsproxy(tsk)->ipc_ns;
	if (is_krg_ipc(&sem_ids(ns)))
		krg_ipc_sem_exit_sem(tsk);

	/* let call __exit_sem in case process has been created
	 * before the Kerrighed loading
	 */
	__exit_sem(tsk);
}
#endif

#ifdef CONFIG_PROC_FS
static int sysvipc_sem_proc_show(struct seq_file *s, void *it)
{
	struct sem_array *sma = it;

	return seq_printf(s,
			  "%10d %10d  %4o %10lu %5u %5u %5u %5u %10lu %10lu\n",
			  sma->sem_perm.key,
			  sma->sem_perm.id,
			  sma->sem_perm.mode,
			  sma->sem_nsems,
			  sma->sem_perm.uid,
			  sma->sem_perm.gid,
			  sma->sem_perm.cuid,
			  sma->sem_perm.cgid,
			  sma->sem_otime,
			  sma->sem_ctime);
}
#endif
