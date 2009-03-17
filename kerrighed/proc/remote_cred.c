/*
 *  kerrighed/proc/remote_cred.c
 *
 *  Copyright (C) 2009 Louis Rilling - Kerlabs
 */
#include <linux/cred.h>
#include <net/krgrpc/rpc.h>

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
