#ifndef __KRG_SYSCALLS_H__
#define __KRG_SYSCALLS_H__

#include <linux/sched.h>
#include <linux/rcupdate.h>

struct caller_creds {
	uid_t caller_uid;
	uid_t caller_euid;
};

static inline int permissions_ok(struct task_struct *task_to_act_on,
				 const struct caller_creds *requester_creds)
{
	const struct cred *cred;
	bool ok;

	rcu_read_lock();
	cred = __task_cred(task_to_act_on);
	ok = ((requester_creds->caller_euid == cred->uid) ||
	      (requester_creds->caller_euid == cred->euid) ||
	      (requester_creds->caller_euid == 0));
	rcu_read_unlock();

	return ok;
}

#endif /* __KRG_SYSCALLS_H__ */
