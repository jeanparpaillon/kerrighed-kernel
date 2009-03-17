/*
 *  kerrighed/capability/capability.c
 *
 *  Copyright (C) 1999-2006 INRIA, Universite de Rennes 1, EDF
 *  Copyright (C) 2006-2007 Louis Rilling - Kerlabs
 */

/** writen by David Margery (c) Inria 2004 */

#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/pid_namespace.h>
#include <linux/rcupdate.h>
#include <kerrighed/capabilities.h>
#ifdef CONFIG_KRG_EPM
#include <linux/pid_namespace.h>
#include <kerrighed/sched.h>
#include <kerrighed/children.h>
#endif
#include <linux/uaccess.h>

#include <kerrighed/krg_syscalls.h>
#include <kerrighed/krg_services.h>
#include <kerrighed/remote_cred.h>
#ifdef CONFIG_KRG_PROC
#include <proc/distant_syscalls.h>
#endif

int can_use_krg_cap(struct task_struct *task, int cap)
{
	return (cap_raised(task->krg_caps.effective, cap)
		&& !atomic_read(&task->krg_cap_unavailable[cap])
		&& !atomic_read(&task->krg_cap_unavailable_private[cap]));
}

void krg_cap_fork(struct task_struct *task, unsigned long clone_flags)
{
	kernel_krg_cap_t *caps = &current->krg_caps;
	kernel_krg_cap_t *new_caps = &task->krg_caps;
	kernel_cap_t new_krg_effective;
	int i;

#ifdef CONFIG_KRG_EPM
	if (krg_current && krg_current->tgid == krg_current->signal->krg_objid)
		/* Migration/restart: do not recompute krg caps */
		return;
#endif

	/*
	 * Compute the new capabilities and reset the private
	 * krg_cap_unavailable array
	 */
	new_krg_effective = cap_intersect(caps->inheritable_effective,
					  caps->inheritable_permitted);

	new_caps->permitted = caps->inheritable_permitted;
	new_caps->effective = new_krg_effective;

	for (i = 0; i < CAP_SIZE; i++)
		atomic_set(&task->krg_cap_unavailable_private[i], 0);
	/* The other fields have been inherited by copy. */
}

int krg_cap_prepare_binprm(struct linux_binprm *bprm)
{
	/* The model needs changes with filesystem support ... */
#if 0
	cap_clear(bprm->krg_cap_forced);
	cap_set_full(bprm->krg_cap_permitted);
	cap_set_full(bprm->krg_cap_effective);
#endif /* 0 */
	return 0;
}

void krg_cap_finish_exec(struct linux_binprm *bprm)
{
	/* The model needs changes with filesystem support ... */
#if 0
	kernel_krg_cap_t *caps = &current->krg_caps;
	kernel_cap_t new_krg_permitted, new_krg_effective;

	/* added by David Margery (c) Inria 2004 */
	/* Updated by Pascal Gallard (c) Inria 2005 */
	task_lock(current);
	new_krg_permitted = cap_intersect(caps->inheritable_permitted,
					  bprm->krg_cap_permitted);
	new_krg_permitted = cap_combine(new_krg_permitted,
					bprm->krg_cap_forced);

	new_krg_effective = cap_intersect(bprm->krg_cap_effective,
					  new_krg_permitted);
	new_krg_effective = cap_intersect(caps->inheritable_effective,
					  new_krg_effective);

	caps->permitted = new_krg_permitted;
	caps->effective = new_krg_effective;
	task_unlock(current);
#endif /* 0 */
}

static int krg_set_cap(struct task_struct *tsk,
		       const kernel_krg_cap_t *requested_cap)
{
	kernel_krg_cap_t *caps = &tsk->krg_caps;
	kernel_cap_t tmp_cap;
	int res;
	int i;

	res = -EINVAL;
	if (!requested_cap)
		goto out;

	if (!cap_issubset(requested_cap->effective, requested_cap->permitted)
	    || !cap_issubset(requested_cap->inheritable_permitted,
			     requested_cap->permitted)
	    || !cap_issubset(requested_cap->inheritable_effective,
			     requested_cap->inheritable_permitted))
		goto out;

	res = -ENOSYS;
	tmp_cap = KRG_CAP_SUPPORTED;
	if (!cap_issubset(requested_cap->permitted, tmp_cap))
		goto out;

	res = -EPERM;
	if (!permissions_ok(tsk))
		goto out;

	task_lock(tsk);

	if (!cap_raised(caps->effective, CAP_CHANGE_KERRIGHED_CAP))
		goto out_unlock;

	res = -EBUSY;
	for (i = 0; i < CAP_SIZE; i++)
		if (atomic_read(&tsk->krg_cap_used[i])
		    && !cap_raised(requested_cap->effective, i))
			goto out_unlock;

	tmp_cap = cap_intersect(caps->permitted, requested_cap->permitted);
	caps->permitted = tmp_cap;
	tmp_cap = cap_intersect(caps->permitted, requested_cap->effective);
	caps->effective = tmp_cap;
	tmp_cap = cap_intersect(caps->permitted,
				requested_cap->inheritable_effective);
	caps->inheritable_effective = tmp_cap;
	tmp_cap = cap_intersect(caps->permitted,
				requested_cap->inheritable_permitted);
	caps->inheritable_permitted = tmp_cap;

	res = 0;

out_unlock:
	task_unlock(tsk);

out:
	return res;
}

static int krg_set_father_cap(struct task_struct *tsk,
			      const kernel_krg_cap_t *requested_cap)
{
	int retval = 0;

	read_lock(&tasklist_lock);
#ifdef CONFIG_KRG_EPM
	if (tsk->parent != baby_sitter) {
#endif
		retval = krg_set_cap(tsk->parent, requested_cap);
		read_unlock(&tasklist_lock);
#ifdef CONFIG_KRG_EPM
	} else {
		struct children_kddm_object *parent_children_obj;
		pid_t real_parent_tgid;
		pid_t parent_pid, real_parent_pid;
		int retval;

		read_unlock(&tasklist_lock);

		parent_children_obj =
			kh_parent_children_readlock(tsk, &real_parent_tgid);
		if (!parent_children_obj)
			/* Parent is init. Do not change init's capabilities! */
			return -EPERM;
		kh_get_parent(parent_children_obj, tsk->pid,
			      &parent_pid, &real_parent_pid);
		retval = kcb_set_pid_cap(real_parent_pid, requested_cap);
		kh_children_unlock(real_parent_tgid);
	}
#endif

	return retval;
}

static int krg_set_pid_cap(pid_t pid, const kernel_krg_cap_t *requested_cap)
{
	struct task_struct *tsk;
	int retval = -ESRCH;

	rcu_read_lock();
	tsk = find_task_by_pid_ns(pid, &init_pid_ns);
	if (tsk)
		retval = krg_set_cap(tsk, requested_cap);
	rcu_read_unlock();
#ifdef CONFIG_KRG_PROC
	if (!tsk)
		retval = kcb_set_pid_cap(pid, requested_cap);
#endif

	return retval;
}

static int krg_get_cap(struct task_struct *tsk, kernel_krg_cap_t *resulting_cap)
{
	kernel_krg_cap_t *caps = &tsk->krg_caps;
	int res;

	task_lock(tsk);

	if (resulting_cap && permissions_ok(tsk)) {
		*resulting_cap = *caps;
		res = 0;
	} else {
		res = -EPERM;
	}

	task_unlock(tsk);

	return res;
}

static int krg_get_father_cap(struct task_struct *son,
			      kernel_krg_cap_t *resulting_cap)
{
	int retval = 0;

	read_lock(&tasklist_lock);
#ifdef CONFIG_KRG_EPM
	if (son->parent != baby_sitter) {
#endif
		retval = krg_get_cap(son->parent, resulting_cap);
		read_unlock(&tasklist_lock);
#ifdef CONFIG_KRG_EPM
	} else {
		struct children_kddm_object *parent_children_obj;
		pid_t real_parent_tgid;
		pid_t parent_pid, real_parent_pid;
		int retval;

		read_unlock(&tasklist_lock);

		parent_children_obj =
			kh_parent_children_readlock(son, &real_parent_tgid);
		if (!parent_children_obj)
			/* Parent is init. */
			return krg_get_cap(child_reaper(son), resulting_cap);
		kh_get_parent(parent_children_obj, son->pid,
			      &parent_pid, &real_parent_pid);
		retval = kcb_get_pid_cap(parent_pid, resulting_cap);
		kh_children_unlock(real_parent_tgid);
	}
#endif

	return retval;
}

static int krg_get_pid_cap(pid_t pid, kernel_krg_cap_t *resulting_cap)
{
	struct task_struct *tsk;
	int retval = -ESRCH;

	rcu_read_lock();
	tsk = find_task_by_pid_ns(pid, &init_pid_ns);
	if (tsk)
		retval = krg_get_cap(tsk, resulting_cap);
	rcu_read_unlock();
#ifdef CONFIG_KRG_PROC
	if (!tsk)
		retval = kcb_get_pid_cap(pid, resulting_cap);
#endif

	return retval;
}

/* Kerrighed syscalls interface */

static int user_to_kernel_krg_cap(const krg_cap_t __user *user_caps,
				  kernel_krg_cap_t *caps)
{
	krg_cap_t ucaps;

	if (copy_from_user(&ucaps, user_caps, sizeof(ucaps)))
		return -EFAULT;

	BUILD_BUG_ON(sizeof(kernel_cap_t) != 2 * sizeof(__u32));

	caps->permitted = (kernel_cap_t){{ ucaps.krg_cap_permitted, 0 }};
	caps->effective = (kernel_cap_t){{ ucaps.krg_cap_effective, 0 }};
	caps->inheritable_permitted =
		(kernel_cap_t){{ ucaps.krg_cap_inheritable_permitted, 0 }};
	caps->inheritable_effective =
		(kernel_cap_t){{ ucaps.krg_cap_inheritable_effective, 0 }};

	return 0;
}

static int proc_set_pid_cap(void __user *arg)
{
	struct krg_cap_pid_desc desc;
	kernel_krg_cap_t caps;
	int r = -EFAULT;

	if (copy_from_user(&desc, arg, sizeof(desc)))
		goto out;

	if (user_to_kernel_krg_cap(desc.caps, &caps))
		goto out;

	r = krg_set_pid_cap(desc.pid, &caps);

out:
	return r;
}

static int proc_set_father_cap(void __user *arg)
{
	kernel_krg_cap_t caps;
	int r;

	r = user_to_kernel_krg_cap(arg, &caps);
	if (!r)
		r = krg_set_father_cap(current, &caps);

	return r;
}

static int proc_set_cap(void __user *arg)
{
	kernel_krg_cap_t caps;
	int r;

	r = user_to_kernel_krg_cap(arg, &caps);
	if (!r)
		r = krg_set_cap(current, &caps);

	return r;
}

static int kernel_to_user_krg_cap(const kernel_krg_cap_t *caps,
				  krg_cap_t __user *user_caps)
{
	krg_cap_t ucaps;
	int r = 0;

	ucaps.krg_cap_permitted = caps->permitted.cap[0];
	ucaps.krg_cap_effective = caps->effective.cap[0];
	ucaps.krg_cap_inheritable_permitted =
		caps->inheritable_permitted.cap[0];
	ucaps.krg_cap_inheritable_effective =
		caps->inheritable_effective.cap[0];

	if (copy_to_user(user_caps, &ucaps, sizeof(ucaps)))
		r = -EFAULT;

	return r;
}

static int proc_get_cap(void __user *arg)
{
	kernel_krg_cap_t caps;
	int r;

	r = krg_get_cap(current, &caps);
	if (!r)
		r = kernel_to_user_krg_cap(&caps, arg);

	return r;
}

static int proc_get_father_cap(void __user *arg)
{
	kernel_krg_cap_t caps;
	int r;

	r = krg_get_father_cap(current, &caps);
	if (!r)
		r = kernel_to_user_krg_cap(&caps, arg);

	return r;
}

static int proc_get_pid_cap(void __user *arg)
{
	struct krg_cap_pid_desc desc;
	kernel_krg_cap_t caps;
	int r = -EFAULT;

	BUG_ON(sizeof(int) != sizeof(pid_t));

	if (copy_from_user(&desc, arg, sizeof(desc)))
		goto out;

	r = krg_get_pid_cap(desc.pid, &caps);

	if (!r)
		r = kernel_to_user_krg_cap(&caps, desc.caps);

out:
	return r;
}

static int proc_get_supported_cap(void __user *arg)
{
	int __user *set = arg;
	return put_user(KRG_CAP_SUPPORTED.cap[0], set);
}

int init_krg_cap(void)
{
	int r;

	r = register_proc_service(KSYS_SET_CAP, proc_set_cap);
	if (r != 0)
		goto out;

	r = register_proc_service(KSYS_GET_CAP, proc_get_cap);
	if (r != 0)
		goto unreg_set_cap;

	r = register_proc_service(KSYS_SET_FATHER_CAP, proc_set_father_cap);
	if (r != 0)
		goto unreg_get_cap;

	r = register_proc_service(KSYS_GET_FATHER_CAP, proc_get_father_cap);
	if (r != 0)
		goto unreg_set_father_cap;

	r = register_proc_service(KSYS_SET_PID_CAP, proc_set_pid_cap);
	if (r != 0)
		goto unreg_get_father_cap;

	r = register_proc_service(KSYS_GET_PID_CAP, proc_get_pid_cap);
	if (r != 0)
		goto unreg_set_pid_cap;

	r = register_proc_service(KSYS_GET_SUPPORTED_CAP,
				  proc_get_supported_cap);
	if (r != 0)
		goto unreg_get_pid_cap;
 out:
	return r;

 unreg_get_pid_cap:
	unregister_proc_service(KSYS_GET_PID_CAP);
 unreg_set_pid_cap:
	unregister_proc_service(KSYS_SET_PID_CAP);
 unreg_get_father_cap:
	unregister_proc_service(KSYS_GET_FATHER_CAP);
 unreg_set_father_cap:
	unregister_proc_service(KSYS_SET_FATHER_CAP);
 unreg_get_cap:
	unregister_proc_service(KSYS_GET_CAP);
 unreg_set_cap:
	unregister_proc_service(KSYS_SET_CAP);
	goto out;
}

void cleanup_krg_cap(void)
{
	unregister_proc_service(KSYS_GET_SUPPORTED_CAP);
	unregister_proc_service(KSYS_GET_PID_CAP);
	unregister_proc_service(KSYS_SET_PID_CAP);
	unregister_proc_service(KSYS_GET_FATHER_CAP);
	unregister_proc_service(KSYS_SET_FATHER_CAP);
	unregister_proc_service(KSYS_GET_CAP);
	unregister_proc_service(KSYS_SET_CAP);

	return;
}
