#ifndef __REMOTE_CRED_H__
#define __REMOTE_CRED_H__

#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/rcupdate.h>

struct rpc_desc;

int pack_creds(struct rpc_desc *desc, const struct cred *cred);
int unpack_creds(struct rpc_desc *desc, struct cred *cred);
const struct cred *unpack_override_creds(struct rpc_desc *desc);

static inline int permissions_ok(struct task_struct *task_to_act_on)
{
	const struct cred *cred = current_cred();
	const struct cred *tcred;
	bool ok;

	rcu_read_lock();
	tcred = __task_cred(task_to_act_on);
	ok = ((cred->euid == tcred->uid) ||
	      (cred->euid == tcred->euid) ||
	      (cred->euid == 0));
	rcu_read_unlock();

	return ok;
}

#endif /* __REMOTE_CRED_H__ */
