/*
 *  kerrighed/proc/remote_cred.c
 *
 *  Copyright (C) 2009 Louis Rilling - Kerlabs
 */
#include <linux/cred.h>
#include <net/krgrpc/rpc.h>
#include <kerrighed/namespace.h>
#ifdef CONFIG_KRG_EPM
#include <linux/user_namespace.h>
#include <linux/pid_namespace.h>
#include <linux/security.h>
#include <kerrighed/ghost.h>

struct epm_action;
#endif

int pack_creds(struct rpc_desc *desc, const struct cred *cred)
{
	return rpc_pack_type(desc, *cred);
}

int unpack_creds(struct rpc_desc *desc, struct cred *cred)
{
	struct cred tmp;
	int err;

	err = rpc_unpack_type(desc, tmp);
	if (err)
		goto out;

	cred->uid = tmp.uid;
	cred->gid = tmp.gid;
	cred->suid = tmp.suid;
	cred->sgid = tmp.sgid;
	cred->euid = tmp.euid;
	cred->egid = tmp.egid;
	cred->fsuid = tmp.fsuid;
	cred->fsgid = tmp.fsgid;
	cred->securebits = tmp.securebits;
	cred->cap_inheritable = tmp.cap_inheritable;
	cred->cap_permitted = tmp.cap_permitted;
	cred->cap_effective = tmp.cap_effective;
	cred->cap_bset = tmp.cap_bset;
#ifdef CONFIG_KEYS
	/* No key sharing accross nodes yet */
#endif
#ifdef CONFIG_SECURITY
	/* No LSM support accross nodes */
#endif
	/* No user struct transfer needed? */
	/* No groups transfer needed? */

out:
	if (err > 0)
		err = -EPIPE;
	return err;
}

const struct cred *unpack_override_creds(struct rpc_desc *desc)
{
	const struct cred *old_cred;
	struct cred *cred;
	int err;

	cred = prepare_creds();
	if (!cred)
		return ERR_PTR(-ENOMEM);
	err = unpack_creds(desc, cred);
	if (err) {
		put_cred(cred);
		return ERR_PTR(err);
	}

	old_cred = override_creds(cred);
	put_cred(cred);

	return old_cred;
}

#ifdef CONFIG_KRG_EPM

int export_cred(struct epm_action *action,
		ghost_t *ghost, struct task_struct *task)
{
	const struct cred *cred = __task_cred(task);
	const struct group_info *groups = cred->group_info;
	int i, err;

#ifdef CONFIG_KEYS
	return -EBUSY;
#endif
#ifdef CONFIG_SECURITY
	if (cred->security)
		return -EBUSY;
#endif
	if (cred->user->user_ns != task_active_pid_ns(task)->krg_ns->root_user_ns)
		return -EPERM;

	err = ghost_write(ghost, cred, sizeof(*cred));
	if (err)
		goto out;

	err = ghost_write(ghost, &groups->ngroups, sizeof(groups->ngroups));
	if (err)
		goto out;
	if (groups->ngroups <= NGROUPS_SMALL) {
		err = ghost_write(ghost,
				  &groups->small_block,
				  sizeof(groups->small_block));
		goto out;
	}
	for (i = 0; i < groups->nblocks; i++) {
		err = ghost_write(ghost,
				  groups->blocks[i],
				  sizeof(*groups->blocks[i] * NGROUPS_PER_BLOCK));
		if (err)
			goto out;
	}

out:
	return err;
}

int import_cred(struct epm_action *action,
		ghost_t *ghost, struct task_struct *task)
{
	struct cred tmp_cred;
	struct cred *cred;
	struct user_struct *user;
	struct group_info *groups;
	int ngroups, i, err;

	err = ghost_read(ghost, &tmp_cred, sizeof(tmp_cred));
	if (err)
		goto out;

	cred = prepare_creds();

	cred->uid = tmp_cred.uid;
	cred->gid = tmp_cred.gid;
	cred->suid = tmp_cred.suid;
	cred->sgid = tmp_cred.sgid;
	cred->euid = tmp_cred.euid;
	cred->egid = tmp_cred.egid;
	cred->fsuid = tmp_cred.fsuid;
	cred->fsgid = tmp_cred.fsgid;
	cred->securebits = tmp_cred.securebits;
	cred->cap_inheritable = tmp_cred.cap_inheritable;
	cred->cap_permitted = tmp_cred.cap_permitted;
	cred->cap_effective = tmp_cred.cap_effective;
	cred->cap_bset = tmp_cred.cap_bset;

#ifdef CONFIG_KEYS
	BUG();
	key_put(cred->thread_keyring);
	cred->thread_keyring = NULL;
	key_put(cred->request_key_auth);
	cred->request_key_auth = NULL;
	release_tgcred(cred->tgcred);
	cred->tgcred = NULL;
#endif

#ifdef CONFIG_SECURITY
	BUG_ON(tmp_cred.security);
	security_cred_free(cred);
	cred->security = NULL;
#endif

	user = alloc_uid(task_active_pid_ns(task)->krg_ns->root_user_ns, cred->uid);
	if (!user) {
		err = -ENOMEM;
		goto out_err;
	}
	free_uid(cred->user);
	cred->user = user;

	err = ghost_read(ghost, &ngroups, sizeof(ngroups));
	if (err)
		goto out_err;
	groups = groups_alloc(ngroups);
	if (!groups) {
		err = -ENOMEM;
		goto out_err;
	}
	if (ngroups <= NGROUPS_SMALL) {
		err = ghost_read(ghost,
				 &groups->small_block,
				 sizeof(groups->small_block));
		if (err)
			goto err_groups;
		else
			goto groups_ok;
	}
	for (i = 0; i < groups->nblocks; i++) {
		err = ghost_read(ghost,
				 groups->blocks[i],
				 sizeof(*groups->blocks[i] * NGROUPS_PER_BLOCK));
		if (err)
			goto err_groups;
	}
groups_ok:
	put_group_info(cred->group_info);
	cred->group_info = groups;

	rcu_assign_pointer(task->real_cred, cred);
	get_cred(cred);
	rcu_assign_pointer(task->cred, cred);
	err = 0;

out:
	return err;

err_groups:
	groups_free(groups);
out_err:
	put_cred(cred);
	goto out;
}

void unimport_cred(struct task_struct *task)
{
	put_cred(task->cred);
	put_cred(task->real_cred);
}

void free_ghost_cred(struct task_struct *ghost)
{
	put_cred(ghost->cred);
	put_cred(ghost->real_cred);
}

#endif /* CONFIG_KRG_EPM */
