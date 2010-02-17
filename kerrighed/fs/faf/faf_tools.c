/** Kerrighed FAF Tools.
 *  @file faf_tools.c
 *
 *  Copyright (C) 2006-2007, Pascal Gallard, Kerlabs.
 */
#include <linux/socket.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <asm/uaccess.h>

#include <net/krgrpc/rpcid.h>
#include <net/krgrpc/rpc.h>

int send_iovec(struct rpc_desc* desc,
	       struct iovec *iovec,
	       int from_user)
{
	void *iov_base;

	if (from_user) {
		iov_base = kmalloc(iovec->iov_len, GFP_KERNEL);
		if (!iov_base)
			return -ENOMEM;

		if (unlikely(copy_from_user(iov_base, iovec->iov_base,
					    iovec->iov_len))) {
			kfree(iov_base);
			return -EFAULT;
		}
	}
	else
		iov_base = iovec->iov_base;

	rpc_pack_type(desc, iovec->iov_len);
	rpc_pack(desc, 0, iov_base, iovec->iov_len);

	if(from_user)
		kfree(iov_base);

	return 0;
}

int recv_iovec(struct rpc_desc* desc,
	       struct iovec *iovec,
	       int to_user)
{
	void *iov_base;
	__kernel_size_t iov_len;
	int r = 0;

	rpc_unpack_type(desc, iov_len);

	iov_base = kmalloc(iov_len, GFP_KERNEL);
	if (!iov_base)
		return -ENOMEM;
	if (to_user) {
		if (iovec->iov_len > iov_len)
			iovec->iov_len = iov_len;
	} else {
		iovec->iov_base = iov_base;
		iovec->iov_len = iov_len;
	}

	rpc_unpack(desc, 0, iov_base, iov_len);

	if (to_user) {
		r = copy_to_user(iovec->iov_base, iov_base, iovec->iov_len);

		kfree(iov_base);
	}

	return r;
}

int free_iovec(struct iovec *iovec)
{
	kfree(iovec->iov_base);
	return 0;
}

int send_msghdr(struct rpc_desc* desc,
		struct msghdr *msghdr,
		int from_user,
		int ctl_from_user)
{
	void *msg_control;
	int i;

	if (ctl_from_user) {
		int r;

		msg_control = kmalloc(msghdr->msg_controllen, GFP_KERNEL);
		BUG_ON(!msg_control);

		r = copy_from_user(msg_control, msghdr->msg_control, msghdr->msg_controllen);
		if (r) {
			printk("send_msghdr: TODO: msg_control\n");
			BUG();
		}

	} else {
		msg_control = msghdr->msg_control;
	}

	rpc_pack(desc, 0, msghdr, sizeof(*msghdr));
	rpc_pack(desc, 0, msghdr->msg_name, msghdr->msg_namelen);
	rpc_pack(desc, 0, msg_control, msghdr->msg_controllen);

	for (i = 0; i < msghdr->msg_iovlen; i++)
		send_iovec(desc, &(msghdr->msg_iov[i]), from_user);

	if (ctl_from_user) {
		kfree(msg_control);
	}

	return 0;
}

int recv_msghdr(struct rpc_desc* desc,
		struct msghdr *msghdr,
		int to_user)
{
	struct msghdr tmp_msg;
	struct msghdr *msg = to_user ? &tmp_msg : msghdr;
	int i;

	rpc_unpack(desc, 0, msg, sizeof(*msg));

	if (to_user) {
		msg->msg_name = msghdr->msg_name;
	} else {
		msg->msg_name = kmalloc(msg->msg_namelen, GFP_KERNEL);
		BUG_ON(!msg->msg_name);
	}

	msg->msg_control = kmalloc(msg->msg_controllen, GFP_KERNEL);
	BUG_ON(!msg->msg_control);

	rpc_unpack(desc, 0, msg->msg_name, msg->msg_namelen);
	rpc_unpack(desc, 0, msg->msg_control, msg->msg_controllen);

	if (to_user) {
		int r;

		if (msg->msg_namelen < msghdr->msg_namelen)
			msghdr->msg_namelen = msg->msg_namelen;

		if (msg->msg_controllen < msghdr->msg_controllen)
			msghdr->msg_controllen = msg->msg_controllen;
		r = copy_to_user(msghdr->msg_control, msg->msg_control,
				 msghdr->msg_controllen);
		if (r) {
			printk("recv_msghdr: TODO: msg_control\n");
			BUG();
		}

		kfree(msg->msg_control);

		BUG_ON(msghdr->msg_iovlen != msg->msg_iovlen);
		for (i = 0; i < msghdr->msg_iovlen; i++)
			recv_iovec(desc, &msghdr->msg_iov[i], 1);

		msghdr->msg_flags = msg->msg_flags;

	} else {
		msg->msg_iov = kmalloc(sizeof(msg->msg_iov[0])*msg->msg_iovlen,
				       GFP_KERNEL);
		memset(msg->msg_iov, 0, sizeof(msg->msg_iov[0])*msg->msg_iovlen);
		BUG_ON(!msg->msg_iov);

		for (i = 0; i < msg->msg_iovlen; i++)
			recv_iovec(desc, &msg->msg_iov[i], 0);
	}

	return 0;
}

int free_msghdr(struct msghdr *msghdr)
{
	int i;

	kfree(msghdr->msg_name);
	kfree(msghdr->msg_control);

	for (i = 0;i < msghdr->msg_iovlen; i++)
		free_iovec(&(msghdr->msg_iov[i]));

	kfree(msghdr->msg_iov);
	return 0;
}
