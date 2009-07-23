/*
 *  kerrighed/epm/signal.c
 *
 *  Copyright (C) 1999-2006 INRIA, Universite de Rennes 1, EDF
 *  Copyright (C) 2006-2007 Pascal Gallard - Kerlabs, Louis Rilling - Kerlabs
 */

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/signal.h>
#include <linux/hrtimer.h>
#include <linux/posix-timers.h>
#include <linux/slab.h>
#ifdef CONFIG_TASKSTATS
#include <linux/taskstats.h>
#include <linux/taskstats_kern.h>
#endif
#include <linux/pid_namespace.h>
#include <linux/pid.h>
#include <linux/user_namespace.h>
#include <linux/rwsem.h>
#include <kerrighed/signal.h>
#include <kerrighed/pid.h>
#include <kerrighed/hotplug.h>
#include <kerrighed/libproc.h>
#include <kerrighed/application.h>
#include <kerrighed/app_shared.h>
#include <kerrighed/action.h>
#include <kerrighed/ghost.h>
#include <net/krgrpc/rpc.h>
#include <kddm/kddm.h>

struct signal_struct_kddm_object {
	struct signal_struct *signal;
	atomic_t count;
	int keep_on_remove;
	struct rw_semaphore remove_sem;
};

static struct kmem_cache *signal_struct_kddm_obj_cachep;

/* Kddm set of 'struct signal_struct' */
static struct kddm_set *signal_struct_kddm_set;

static struct signal_struct_kddm_object *signal_struct_kddm_object_alloc(void)
{
	struct signal_struct_kddm_object *obj;

	obj = kmem_cache_alloc(signal_struct_kddm_obj_cachep, GFP_KERNEL);
	if (obj) {
		obj->signal = NULL;
	/*	atomic_set(&obj->count, 1); */
		obj->keep_on_remove = 0;
		init_rwsem(&obj->remove_sem);
	}
	return obj;
}

static struct signal_struct *signal_struct_alloc(void)
{
	struct signal_struct *sig;

	sig = kmem_cache_alloc(signal_cachep, GFP_KERNEL);
	if (!sig)
		return NULL;

/*	atomic_set(&obj->signal->count, 1); */
/*	atomic_set(&obj->signal->live, 1); */
	init_waitqueue_head(&sig->wait_chldexit);
/*	obj->signal->flags = 0; */
/*	obj->signal->group_exit_code = 0; */
	sig->group_exit_task = NULL;
/*	obj->signal->group_stop_count = 0; */
	sig->curr_target = NULL;
	init_sigpending(&sig->shared_pending);

	posix_cpu_timers_init_group(sig);
	INIT_LIST_HEAD(&sig->posix_timers);

	hrtimer_init(&sig->real_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	sig->leader_pid = NULL;

	sig->tty_old_pgrp = NULL;
	sig->tty = NULL;
/*	obj->signal->leader = 0;	/\* session leadership doesn't inherit *\/ */
#ifdef CONFIG_TASKSTATS
	sig->stats = NULL;
#endif
#ifdef CONFIG_AUDIT
	sig->tty_audit_buf = NULL;
#endif

	return sig;
}

static void signal_struct_attach_object(struct signal_struct *sig,
					struct signal_struct_kddm_object *obj,
					objid_t objid)
{
	sig->krg_objid = objid;
	sig->kddm_obj = obj;
	obj->signal = sig;
}

/*
 * @author Pascal Gallard
 */
static int signal_struct_alloc_object(struct kddm_obj *obj_entry,
				      struct kddm_set *set, objid_t objid)
{
	struct signal_struct_kddm_object *obj;
	struct signal_struct *sig;

	obj = signal_struct_kddm_object_alloc();
	if (!obj)
		return -ENOMEM;

	sig = signal_struct_alloc();
	if (!sig) {
		kmem_cache_free(signal_struct_kddm_obj_cachep, obj);
		return -ENOMEM;
	}

	signal_struct_attach_object(sig, obj, objid);

	obj_entry->object = obj;

	return 0;
}

/*
 * @author Pascal Gallard
 */
static int signal_struct_first_touch(struct kddm_obj *obj_entry,
				     struct kddm_set *set, objid_t objid,
				     int flags)
{
	struct signal_struct_kddm_object *obj;

	obj = signal_struct_kddm_object_alloc();
	if (!obj)
		return -ENOMEM;
	atomic_set(&obj->count, 1);

	obj_entry->object = obj;

	return 0;
}

/*
 * Lock on the dest signal_struct must be held. No other access
 * to dest is allowed in the import time.
 * @author Pascal Gallard
 */
static int signal_struct_import_object(struct kddm_obj *obj_entry,
				       struct rpc_desc *desc)
{
	struct signal_struct_kddm_object *obj = obj_entry->object;
	struct signal_struct *dest = obj->signal;
	struct signal_struct tmp_sig;
	int retval;

	retval = rpc_unpack_type(desc, tmp_sig);
	if (retval)
		return retval;
#ifdef CONFIG_TASKSTATS
	if (tmp_sig.stats) {
		retval = -ENOMEM;
		tmp_sig.stats = kmem_cache_alloc(taskstats_cache, GFP_KERNEL);
		if (!tmp_sig.stats)
			return retval;
		retval = rpc_unpack_type(desc, *tmp_sig.stats);
		if (retval) {
			kmem_cache_free(taskstats_cache, tmp_sig.stats);
			return retval;
		}
	}
#endif
	retval = rpc_unpack_type(desc, obj->count);
	if (retval)
		return retval;

	/* We are only modifying a copy of the real signal struct. All pointers
	 * should be left NULL. */
	/* TODO: with distributed threads this will need more locking */
	atomic_set(&dest->count, atomic_read(&tmp_sig.count));
	atomic_set(&dest->live, atomic_read(&tmp_sig.live));

	dest->group_exit_code = tmp_sig.group_exit_code;
	dest->notify_count = tmp_sig.notify_count;
	dest->group_stop_count = tmp_sig.group_stop_count;
	dest->flags = tmp_sig.flags;

	dest->it_real_incr = tmp_sig.it_real_incr;
	dest->it_prof_expires = tmp_sig.it_prof_expires;
	dest->it_virt_expires = tmp_sig.it_virt_expires;
	dest->it_prof_incr = tmp_sig.it_prof_incr;
	dest->it_virt_incr = tmp_sig.it_virt_incr;
	dest->cputimer.cputime = tmp_sig.cputimer.cputime;
	dest->cputimer.running = tmp_sig.cputimer.running;
	dest->cputime_expires = tmp_sig.cputime_expires;

	dest->leader = tmp_sig.leader;

	dest->utime = tmp_sig.utime;
	dest->stime = tmp_sig.stime;
	dest->cutime = tmp_sig.cutime;
	dest->cstime = tmp_sig.cstime;
	dest->gtime = tmp_sig.gtime;
	dest->cgtime = tmp_sig.cgtime;
	dest->nvcsw = tmp_sig.nvcsw;
	dest->nivcsw = tmp_sig.nivcsw;
	dest->cnvcsw = tmp_sig.cnvcsw;
	dest->cnivcsw = tmp_sig.cnivcsw;
	dest->min_flt = tmp_sig.min_flt;
	dest->maj_flt = tmp_sig.maj_flt;
	dest->cmin_flt = tmp_sig.cmin_flt;
	dest->cmaj_flt = tmp_sig.cmaj_flt;
	dest->inblock = tmp_sig.inblock;
	dest->oublock = tmp_sig.oublock;
	dest->cinblock = tmp_sig.cinblock;
	dest->coublock = tmp_sig.coublock;
	/* ioac may be an empty struct */
	if (sizeof(dest->ioac))
		dest->ioac = tmp_sig.ioac;

	dest->sum_sched_runtime = tmp_sig.sum_sched_runtime;

	memcpy(dest->rlim, tmp_sig.rlim, sizeof(dest->rlim));
#ifdef CONFIG_BSD_PROCESS_ACCT
	dest->pacct = tmp_sig.pacct;
#endif
#ifdef CONFIG_TASKSTATS
	if (tmp_sig.stats) {
		if (dest->stats) {
			memcpy(dest->stats, tmp_sig.stats,
			       sizeof(*dest->stats));
			kmem_cache_free(taskstats_cache, tmp_sig.stats);
		} else {
			dest->stats = tmp_sig.stats;
		}
	}
#endif
#ifdef CONFIG_AUDIT
	dest->audit_tty = tmp_sig.audit_tty;
#endif

	return 0;
}

/*
 * @author Pascal Gallard
 */
static int signal_struct_export_object(struct rpc_desc *desc,
				       struct kddm_obj *obj_entry)
{
	struct signal_struct_kddm_object *obj = obj_entry->object;
	struct task_struct *tsk;
	unsigned long flags;
	int retval;

	rcu_read_lock();
	tsk = find_task_by_pid_ns(obj->signal->krg_objid, &init_pid_ns);
	/*
	 * We may find no task in the middle of a migration. In that case, kddm
	 * locking is enough since neither userspace nor the kernel will access
	 * this copy.
	 */
	if (tsk)
		get_task_struct(tsk);
	rcu_read_unlock();
	if (tsk && !lock_task_sighand(tsk, &flags))
		BUG();
	retval = rpc_pack_type(desc, *obj->signal);
#ifdef CONFIG_TASKSTATS
	if (!retval && obj->signal->stats)
		retval = rpc_pack_type(desc, *obj->signal->stats);
#endif
	if (tsk) {
		unlock_task_sighand(tsk, &flags);
		put_task_struct(tsk);
	}
	if (!retval)
		retval = rpc_pack_type(desc, obj->count);

	return retval;
}

void krg_signal_pin(struct signal_struct *sig)
{
	struct signal_struct_kddm_object *obj = sig->kddm_obj;
	BUG_ON(!obj);
	down_read(&obj->remove_sem);
}

void krg_signal_unpin(struct signal_struct *sig)
{
	struct signal_struct_kddm_object *obj = sig->kddm_obj;
	BUG_ON(!obj);
	up_read(&obj->remove_sem);
}

static int signal_struct_remove_object(void *object,
				       struct kddm_set *set, objid_t objid)
{
	struct signal_struct_kddm_object *obj = object;

	/* Ensure that no thread uses this signal_struct copy */
	down_write(&obj->remove_sem);
	up_write(&obj->remove_sem);

	if (!obj->keep_on_remove) {
		struct signal_struct *sig = obj->signal;

		WARN_ON(!list_empty(&sig->shared_pending.list));
		flush_sigqueue(&sig->shared_pending);
#ifdef CONFIG_TASKSTATS
		taskstats_tgid_free(sig);
#endif
#ifdef CONFIG_AUDIT
		BUG_ON(sig->tty_audit_buf);
#endif
		put_pid(sig->tty_old_pgrp);
		kmem_cache_free(signal_cachep, sig);
	}
	kmem_cache_free(signal_struct_kddm_obj_cachep, obj);

	return 0;
}

static struct iolinker_struct signal_struct_io_linker = {
	.first_touch   = signal_struct_first_touch,
	.linker_name   = "sig ",
	.linker_id     = SIGNAL_STRUCT_LINKER,
	.alloc_object  = signal_struct_alloc_object,
	.export_object = signal_struct_export_object,
	.import_object = signal_struct_import_object,
	.remove_object = signal_struct_remove_object,
	.default_owner = global_pid_default_owner,
};

static
struct signal_struct_kddm_object *
____krg_signal_alloc(struct signal_struct *sig, objid_t id)
{
	struct signal_struct_kddm_object *obj;

	/* Create the signal object */
	obj = _kddm_grab_object(signal_struct_kddm_set, id);
	BUG_ON(!obj);
	/* Must be a first touch */
	BUG_ON(obj->signal);
	signal_struct_attach_object(sig, obj, id);

	return obj;
}

struct signal_struct *cr_signal_alloc(pid_t tgid)
{
	struct signal_struct_kddm_object *obj;
	struct signal_struct *sig;

	sig = signal_struct_alloc();
	if (!sig)
		return NULL;

	obj = ____krg_signal_alloc(sig, tgid);
	BUG_ON(!obj);

	return sig;
}

void cr_signal_free(pid_t id)
{
	_kddm_remove_frozen_object(signal_struct_kddm_set, id);
}

static void __krg_signal_alloc(struct task_struct *task, struct pid *pid)
{
	struct signal_struct_kddm_object *obj;
	struct signal_struct *sig = task->signal;
	pid_t tgid = pid_nr(pid);

	/*
	 * Exclude kernel threads and local pids from using signal_struct
	 * kddm objects.
	 */
	/*
	 * At this stage, task->mm may point to the mm of a
	 * task being duplicated instead of the mm of task for which this struct
	 * is being allocated, but we only need to know whether it is NULL or
	 * not, which will be the same after copy_mm.
	 */
	if (!(tgid & GLOBAL_PID_MASK) || !task->mm) {
		BUG_ON(krg_current);
		sig->krg_objid = 0;
		sig->kddm_obj = NULL;
		return;
	}

	obj = ____krg_signal_alloc(sig, tgid);
	BUG_ON(!obj);
	krg_signal_unlock(tgid);
}

static void *cluster_started;

/*
 * Alloc a dedicated signal_struct to task_struct task.
 * @author Pascal Gallard
 */
void krg_signal_alloc(struct task_struct *task, struct pid *pid,
		      unsigned long clone_flags)
{
	if (!cluster_started)
		return;

	if (krg_current && krg_current->tgid == krg_current->signal->krg_objid)
		/*
		 * This is a process migration or restart: signal_struct is
		 * already setup.
		 */
		return;

	if (!krg_current && (clone_flags & CLONE_THREAD))
		/* New thread: already done in copy_signal() */
		return;

	__krg_signal_alloc(task, pid);
}

/*
 * Get and lock a signal structure for a given process
 * @author Pascal Gallard
 */
struct signal_struct *krg_signal_readlock(pid_t tgid)
{
	struct signal_struct_kddm_object *obj;

	/* Filter well known cases of no signal_struct kddm object. */
	if (!(tgid & GLOBAL_PID_MASK))
		return NULL;

	obj = _kddm_get_object_no_ft(signal_struct_kddm_set, tgid);
	if (!obj) {
		_kddm_put_object(signal_struct_kddm_set, tgid);
		return NULL;
	}
	BUG_ON(!obj->signal);

	return obj->signal;
}

static struct signal_struct_kddm_object *__krg_signal_writelock(pid_t tgid)
{
	struct signal_struct_kddm_object *obj;

	obj = _kddm_grab_object_no_ft(signal_struct_kddm_set, tgid);
	if (!obj) {
		_kddm_put_object(signal_struct_kddm_set, tgid);
		return NULL;
	}
	BUG_ON(!obj->signal);
	return obj;
}

/*
 * Grab and lock a signal structure for a given process
 * @author Pascal Gallard
 */
struct signal_struct *krg_signal_writelock(pid_t tgid)
{
	struct signal_struct_kddm_object *obj;

	/* Filter well known cases of no signal_struct kddm object. */
	if (!(tgid & GLOBAL_PID_MASK))
		return NULL;

	obj = __krg_signal_writelock(tgid);
	if (!obj)
		return NULL;

	return obj->signal;
}

/*
 * unlock a signal structure for a given process
 * @author Pascal Gallard
 */
void krg_signal_unlock(pid_t tgid)
{
	_kddm_put_object(signal_struct_kddm_set, tgid);
}

/* Assumes that the associated kddm object is write locked. */
void krg_signal_share(struct task_struct *task)
{
	struct signal_struct_kddm_object *obj = task->signal->kddm_obj;
	int count;

	count = atomic_inc_return(&obj->count);
}

pid_t __krg_signal_exit(pid_t id)
{
	struct signal_struct_kddm_object *obj;
	int count;

	obj = __krg_signal_writelock(id);
	BUG_ON(!obj);
	count = atomic_dec_return(&obj->count);
	if (count == 0) {
		krg_signal_unlock(id);
		BUG_ON(obj->keep_on_remove);
		/* Free the kddm object but keep the signal_struct so that
		 * __exit_signal releases it properly. */
		obj->keep_on_remove = 1;
		_kddm_remove_object(signal_struct_kddm_set, id);

		return 0;
	}

	return id;
}

pid_t krg_signal_exit(struct task_struct *task)
{
	struct signal_struct *sig = task->signal;
	pid_t ret = 0;

	if (sig->kddm_obj)
		ret = __krg_signal_exit(sig->krg_objid);

	return ret;
}

void krg_signal_setup(struct task_struct *task)
{
	struct signal_struct *sig = task->signal;

	if (thread_group_leader(task)) {
		__krg_signal_alloc(task, task_pid(task));
	} else if (sig->kddm_obj) {
		krg_signal_writelock(task->tgid);
		krg_signal_share(task);
		krg_signal_unlock(task->tgid);
	}
}

/* EPM actions */

/* individual struct sigpending */

static int export_sigqueue(ghost_t *ghost, struct sigqueue *sig)
{
	int err = -EBUSY;

	if (sig->user->user_ns != &init_user_ns)
		goto out;

	err = ghost_write(ghost, &sig->info, sizeof(sig->info));
	if (err)
		goto out;
	err = ghost_write(ghost, &sig->user->uid, sizeof(sig->user->uid));

out:
	return err;
}

static int import_sigqueue(ghost_t *ghost, struct sigqueue *sig)
{
	struct user_struct *user;
	uid_t uid;
	int err;

	err = ghost_read(ghost, &sig->info, sizeof(sig->info));
	if (err)
		goto out;

	err = ghost_read(ghost, &uid, sizeof(uid));
	if (err)
		goto out;
	user = alloc_uid(&init_user_ns, uid);
	if (!user) {
		err = -ENOMEM;
		goto out;
	}
	atomic_inc(&user->sigpending);

	atomic_dec(&sig->user->sigpending);
	free_uid(sig->user);

	sig->user = user;

out:
	return err;
}

static int export_sigpending(ghost_t *ghost,
			     struct task_struct *task,
			     struct sigpending *pending)
{
	struct sigpending tmp_queue;
	int nr_sig;
	struct sigqueue *q;
	unsigned long flags;
	int err;

	INIT_LIST_HEAD(&tmp_queue.list);
	nr_sig = 0;
	if (!lock_task_sighand(task, &flags))
		BUG();
	tmp_queue.signal = pending->signal;
	list_for_each_entry(q, &pending->list, list) {
		if (q->flags & SIGQUEUE_PREALLOC) {
			unlock_task_sighand(task, &flags);
			err = -EBUSY;
			goto out;
		}
		nr_sig++;
	}
	list_splice_init(&pending->list, &tmp_queue.list);
	unlock_task_sighand(task, &flags);

	err = ghost_write(ghost, &tmp_queue.signal, sizeof(tmp_queue.signal));
	if (err)
		goto out_splice;

	err = ghost_write(ghost, &nr_sig, sizeof(nr_sig));
	if (err)
		goto out_splice;

	list_for_each_entry(q, &tmp_queue.list, list) {
		err = export_sigqueue(ghost, q);
		if (err)
			goto out_splice;
	}

out_splice:
	if (!lock_task_sighand(task, &flags))
		BUG();
	sigorsets(&pending->signal, &pending->signal, &tmp_queue.signal);
	list_splice(&tmp_queue.list, &pending->list);
	recalc_sigpending_tsk(task);
	unlock_task_sighand(task, &flags);

out:
	return err;
}

static int import_sigpending(ghost_t *ghost,
			     struct task_struct *task,
			     struct sigpending *pending)
{
	int nr_sig;
	struct sigqueue *q;
	int i;
	int err;

	err = ghost_read(ghost, &pending->signal, sizeof(pending->signal));
	if (err)
		goto cleanup_queue;

	err = ghost_read(ghost, &nr_sig, sizeof(nr_sig));
	if (err)
		goto cleanup_queue;

	INIT_LIST_HEAD(&pending->list);
	for (i = 0; i < nr_sig; i++) {
		q = __sigqueue_alloc(current, GFP_KERNEL, 0);
		if (!q) {
			err = -ENOMEM;
			goto free_queue;
		}
		err = import_sigqueue(ghost, q);
		if (err) {
			__sigqueue_free(q);
			goto free_queue;
		}
		list_add_tail(&q->list, &pending->list);
	}

out:
	return err;

cleanup_queue:
	init_sigpending(pending);
	goto out;

free_queue:
	flush_sigqueue(pending);
	goto out;
}

static void unimport_sigpending(struct task_struct *task,
				struct sigpending *pending)
{
	flush_sigqueue(pending);
}

/* shared signals (struct signal_struct) */

static int export_posix_timers(ghost_t *ghost, struct task_struct *task)
{
	int err = 0;
	spin_lock_irq(&task->sighand->siglock);
	if (!list_empty(&task->signal->posix_timers))
		err = -EBUSY;
	spin_unlock_irq(&task->sighand->siglock);
	return err;
}

static int import_posix_timers(ghost_t *ghost, struct task_struct *task)
{
	BUG_ON(!list_empty(&task->signal->posix_timers));
	return 0;
}

static void unimport_posix_timers(struct task_struct *task)
{
}

#ifdef CONFIG_TASKSTATS
static int cr_export_taskstats(ghost_t *ghost, struct signal_struct *sig)
{
	return ghost_write(ghost, sig->stats, sizeof(*sig->stats));
}

static int cr_import_taskstats(ghost_t *ghost, struct signal_struct *sig)
{
	struct taskstats *stats;
	int err = -ENOMEM;

	stats = kmem_cache_alloc(taskstats_cache, GFP_KERNEL);
	if (!stats)
		goto out;

	err = ghost_read(ghost, stats, sizeof(*stats));
	if (!err)
		sig->stats = stats;
	else
		kmem_cache_free(taskstats_cache, stats);

out:
	return err;
}
#endif

static int cr_export_later_signal_struct(struct epm_action *action,
					 ghost_t *ghost,
					 struct task_struct *task)
{
	int r;
	long key;

	BUG_ON(action->type != EPM_CHECKPOINT);
	BUG_ON(action->checkpoint.shared != CR_SAVE_LATER);

	key = (long)(task->signal->krg_objid);

	r = ghost_write(ghost, &key, sizeof(long));
	if (r)
		goto err;

	r = add_to_shared_objects_list(task->application,
				       SIGNAL_STRUCT, key, 1 /*is_local*/,
				       task, NULL);

	if (r == -ENOKEY) /* the signal_struct was already in the list */
		r = 0;
err:
	return r;
}

int export_signal_struct(struct epm_action *action,
			 ghost_t *ghost, struct task_struct *tsk)
{
	unsigned long krg_objid = tsk->signal->krg_objid;
	int r;

	if (action->type == EPM_CHECKPOINT
	    && action->checkpoint.shared == CR_SAVE_LATER) {
		r = cr_export_later_signal_struct(action, ghost, tsk);
		return r;
	}

	r = ghost_write(ghost, &krg_objid, sizeof(krg_objid));
	if (r)
		goto err_write;

	switch (action->type) {
	case EPM_MIGRATE:
		r = export_sigpending(ghost, tsk, &tsk->signal->shared_pending);
		if (r)
			goto err_write;
		r = export_posix_timers(ghost, tsk);
		break;
	case EPM_CHECKPOINT: {
		struct signal_struct *sig =
			krg_signal_readlock(krg_objid);
		r = ghost_write(ghost, sig, sizeof(*sig));
		if (!r)
			r = export_sigpending(ghost,
					      tsk,
					      &tsk->signal->shared_pending);
#ifdef CONFIG_TASKSTATS
		if (!r && sig->stats)
			r = cr_export_taskstats(ghost, sig);
#endif
		if (!r)
			r = export_posix_timers(ghost, tsk);
		krg_signal_unlock(krg_objid);
		break;
	} default:
		break;
	}

err_write:
	return r;
}

static int cr_link_to_signal_struct(struct epm_action *action,
				    ghost_t *ghost,
				    struct task_struct *tsk)
{
	int r;
	long key;
	struct signal_struct *sig;

	r = ghost_read(ghost, &key, sizeof(long));
	if (r)
		goto err;

	sig = get_imported_shared_object(action->restart.app,
					 SIGNAL_STRUCT, key);

	if (!sig) {
		r = -E_CR_BADDATA;
		goto err;
	}

	if (!sig->leader_pid) {
		BUG_ON(tsk->tgid != tsk->pid);
		sig->leader_pid = task_pid(tsk);
	}

	tsk->signal = sig;

	krg_signal_writelock(tsk->tgid);
	atomic_inc(&tsk->signal->count);
	atomic_inc(&tsk->signal->live);
	krg_signal_share(tsk);
	krg_signal_unlock(tsk->tgid);
err:
	return r;
}

int import_signal_struct(struct epm_action *action,
			 ghost_t *ghost, struct task_struct *tsk)
{
	unsigned long krg_objid;
	struct signal_struct *sig;
	int r;

	if (action->type == EPM_CHECKPOINT
	    && action->restart.shared == CR_LINK_ONLY) {
		r = cr_link_to_signal_struct(action, ghost, tsk);
		return r;
	}

	r = ghost_read(ghost, &krg_objid, sizeof(krg_objid));
	if (r)
		goto err_read;

	switch (action->type) {
	case EPM_MIGRATE:
		/* TODO: this will need more locking with distributed threads */
		sig = krg_signal_writelock(krg_objid);
		BUG_ON(!sig);

		WARN_ON(sig->group_exit_task);
		WARN_ON(!list_empty(&sig->shared_pending.list));
		flush_sigqueue(&sig->shared_pending);
		r = import_sigpending(ghost, tsk, &sig->shared_pending);
		if (r)
			goto out_mig_unlock;

		if (!sig->leader_pid)
			sig->leader_pid = task_pid(tsk);

		/*
		 * This will need proper tty handling once global control ttys
		 * will exist.
		 */
		sig->tty = NULL;

		tsk->signal = sig;

		r = import_posix_timers(ghost, tsk);

out_mig_unlock:
		krg_signal_unlock(krg_objid);
		break;

	case EPM_REMOTE_CLONE:
		/*
		 * The structure will be partly copied when creating the
		 * active process.
		 */
		sig = krg_signal_readlock(krg_objid);
		krg_signal_unlock(krg_objid);
		BUG_ON(!sig);
		tsk->signal = sig;
		break;

	case EPM_CHECKPOINT: {
		struct signal_struct tmp_sig;

		sig = cr_signal_alloc(tsk->tgid);

		r = ghost_read(ghost, &tmp_sig, sizeof(tmp_sig));
		if (r)
			goto err_free_signal;

		atomic_set(&sig->count, 1);
		atomic_set(&sig->live, 1);

		sig->group_exit_code = tmp_sig.group_exit_code;
		WARN_ON(tmp_sig.group_exit_task);
		sig->notify_count = tmp_sig.notify_count;
		sig->group_stop_count = tmp_sig.group_stop_count;
		sig->flags = tmp_sig.flags;

		r = import_sigpending(ghost, tsk, &sig->shared_pending);
		if (r)
			goto err_free_signal;

		sig->it_real_incr = tmp_sig.it_real_incr;
		sig->it_prof_expires = tmp_sig.it_prof_expires;
		sig->it_virt_expires = tmp_sig.it_virt_expires;
		sig->it_prof_incr = tmp_sig.it_prof_incr;
		sig->it_virt_incr = tmp_sig.it_virt_incr;
		sig->cputimer.cputime = tmp_sig.cputimer.cputime;
		sig->cputimer.running = tmp_sig.cputimer.running;
		sig->cputime_expires = tmp_sig.cputime_expires;

		/*
		 * This will need proper tty handling once global control ttys
		 * will exist.
		 * The IO-linker already initialized those fields to NULL.
		 */
		/* sig->tty = NULL; */
		/* sig->tty_old_pgrp = NULL; */

		sig->leader = tmp_sig.leader;

		sig->utime = tmp_sig.utime;
		sig->stime = tmp_sig.stime;
		sig->cutime = tmp_sig.cutime;
		sig->cstime = tmp_sig.cstime;
		sig->gtime = tmp_sig.gtime;
		sig->cgtime = tmp_sig.cgtime;
		sig->nvcsw = tmp_sig.nvcsw;
		sig->nivcsw = tmp_sig.nivcsw;
		sig->cnvcsw = tmp_sig.cnvcsw;
		sig->cnivcsw = tmp_sig.cnivcsw;
		sig->min_flt = tmp_sig.min_flt;
		sig->maj_flt = tmp_sig.maj_flt;
		sig->cmin_flt = tmp_sig.cmin_flt;
		sig->cmaj_flt = tmp_sig.cmaj_flt;
		sig->inblock = tmp_sig.inblock;
		sig->oublock = tmp_sig.oublock;
		sig->cinblock = tmp_sig.cinblock;
		sig->coublock = tmp_sig.coublock;
		/* ioac may be an empty struct */
		if (sizeof(sig->ioac))
			sig->ioac = tmp_sig.ioac;

		sig->sum_sched_runtime = tmp_sig.sum_sched_runtime;

		memcpy(sig->rlim, tmp_sig.rlim, sizeof(sig->rlim));
#ifdef CONFIG_BSD_PROCESS_ACCT
		sig->pacct = tmp_sig.pacct;
#endif
#ifdef CONFIG_TASKSTATS
		if (tmp_sig.stats) {
			r = cr_import_taskstats(ghost, sig);
			if (r)
				goto err_free_signal;
		}
#endif
#ifdef CONFIG_AUDIT
		sig->audit_tty = tmp_sig.audit_tty;
#endif

		tsk->signal = sig;

		r = import_posix_timers(ghost, tsk);
		if (r)
			goto err_free_signal;

		krg_signal_unlock(krg_objid);
		break;

err_free_signal:
		cr_signal_free(tsk->tgid);
		goto err_read;

	} default:
		PANIC("Case not supported: %d\n", action->type);
	}

err_read:
	return r;
}

void unimport_signal_struct(struct task_struct *task)
{
	/*
	 * TODO: for restart, we must free the created kddm signal_struct
	 * object.
	 */
	unimport_posix_timers(task);
	unimport_sigpending(task, &task->signal->shared_pending);
}

static int cr_export_now_signal_struct(struct epm_action *action,
				       ghost_t *ghost,
				       struct task_struct *task,
				       union export_args *args)
{
	int r;
	r = export_signal_struct(action, ghost, task);
	return r;
}

static int cr_import_now_signal_struct(struct epm_action *action,
				       ghost_t *ghost,
				       struct task_struct *fake,
				       void **returned_data)
{
	int r;
	BUG_ON(*returned_data != NULL);

	r = import_signal_struct(action, ghost, fake);
	if (r)
		goto err;

	*returned_data = fake->signal;
err:
	return r;
}

static int cr_import_complete_signal_struct(struct task_struct *fake,
					    void *_sig)
{
	pid_t signal_id = 0;
	struct signal_struct *sig = _sig;

	signal_id = __krg_signal_exit(sig->krg_objid);

	atomic_dec(&sig->count);
	atomic_dec(&sig->live);

	if (signal_id)
		krg_signal_unlock(signal_id);

	return 0;
}

static int cr_delete_signal_struct(struct task_struct *fake, void *_sig)
{
	pid_t signal_id = 0;
	struct signal_struct *sig = _sig;

	fake->signal = sig;
	/*
	 * Prevent
	 * posix_cpu_timers_exit_group()
	 *   thread_group_cputimer()
	 *     thread_group_cputime()
	 * from running through the thread group.
	 */
	fake->sighand = NULL;
	INIT_LIST_HEAD(&fake->cpu_timers[0]);
	INIT_LIST_HEAD(&fake->cpu_timers[1]);
	INIT_LIST_HEAD(&fake->cpu_timers[2]);

	signal_id = __krg_signal_exit(sig->krg_objid);

	atomic_dec(&sig->count);
	atomic_dec(&sig->live);

	if (signal_id)
		krg_signal_unlock(signal_id);

	posix_cpu_timers_exit_group(fake);

	flush_sigqueue(&sig->shared_pending);
	taskstats_tgid_free(sig);
	__cleanup_signal(sig);

	return 0;
}

struct shared_object_operations cr_shared_signal_struct_ops = {
	.restart_data_size = 0,
	.export_now        = cr_export_now_signal_struct,
	.import_now        = cr_import_now_signal_struct,
	.import_complete   = cr_import_complete_signal_struct,
	.delete            = cr_delete_signal_struct,
};

/* private signals */

int export_private_signals(struct epm_action *action,
			   ghost_t *ghost,
			   struct task_struct *task)
{
	int err = 0;

	switch (action->type) {
	case EPM_MIGRATE:
	case EPM_CHECKPOINT:
		err = export_sigpending(ghost, task, &task->pending);
		break;
	default:
		break;
	}

	return err;
}

int import_private_signals(struct epm_action *action,
			   ghost_t *ghost,
			   struct task_struct *task)
{
	int err = 0;

	switch (action->type) {
	case EPM_MIGRATE:
	case EPM_CHECKPOINT:
		err = import_sigpending(ghost, task, &task->pending);
		break;
	default:
		break;
	}

	return err;
}

void unimport_private_signals(struct task_struct *task)
{
	unimport_sigpending(task, &task->pending);
}

void register_signal_hooks(void)
{
	hook_register(&cluster_started, (void *)true);
}

int epm_signal_start(void)
{
	unsigned long cache_flags = SLAB_PANIC;

#ifdef CONFIG_DEBUG_SLAB
	cache_flags |= SLAB_POISON;
#endif
	signal_struct_kddm_obj_cachep = KMEM_CACHE(signal_struct_kddm_object,
						   cache_flags);

	register_io_linker(SIGNAL_STRUCT_LINKER, &signal_struct_io_linker);

	signal_struct_kddm_set = create_new_kddm_set(kddm_def_ns,
						     SIGNAL_STRUCT_KDDM_ID,
						     SIGNAL_STRUCT_LINKER,
						     KDDM_CUSTOM_DEF_OWNER,
						     0,
						     KDDM_LOCAL_EXCLUSIVE);
	if (IS_ERR(signal_struct_kddm_set))
		OOM;

	return 0;
}

void epm_signal_exit(void)
{
	return;
}
