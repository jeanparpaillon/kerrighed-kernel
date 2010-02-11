/** Kerrighed FAF Tools.
 *  @file faf_tools.c
 *
 *  Copyright (C) 2006-2007, Pascal Gallard, Kerlabs.
 */
#include <linux/socket.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <net/krgrpc/rpc.h>
#include "faf_tools.h"

static
int send_user_iov(struct rpc_desc *desc, struct msghdr *msg, int total_len)
{
	void *page;
	void __user *iov_base;
	int i, iov_len, iov_offset, page_offset, max_page_offset, sent, err = 0;

	page = (void *)__get_free_page(GFP_KERNEL);
	if (!page)
		return -ENOMEM;

	i = 0;
	iov_offset = 0;
	for (sent = 0; sent < total_len; sent += PAGE_SIZE) {
		max_page_offset = PAGE_SIZE;
		if (sent + max_page_offset > total_len)
			max_page_offset = total_len - sent;

		page_offset = 0;
		while (page_offset < max_page_offset) {
			BUG_ON(i >= msg->msg_iovlen);

			iov_base = (__force void __user *)msg->msg_iov[i].iov_base
				+ iov_offset;
			iov_len = msg->msg_iov[i].iov_len - iov_offset;

			if (iov_len > max_page_offset - page_offset) {
				iov_len = max_page_offset - page_offset;
				iov_offset += iov_len;
			} else {
				i++;
				iov_offset = 0;
			}

			if (copy_from_user(page + page_offset,
					   iov_base, iov_len)) {
				err = -EFAULT;
				goto out_free;
			}

			page_offset += iov_len;
		}

		err = rpc_pack(desc, 0, page, max_page_offset);
		if (err)
			break;
	}

out_free:
	free_page((unsigned long)page);

	return err;
}

static
int send_kernel_iov(struct rpc_desc *desc, struct msghdr *msg, int total_len)
{
	int iov_len, i, sent, err = 0;

	/* FAF server is supposed to have page-backed iovecs */
	for (sent = 0, i = 0; sent < total_len; sent += PAGE_SIZE, i++) {
		BUG_ON(i >= msg->msg_iovlen);

		iov_len = msg->msg_iov[i].iov_len;
		BUG_ON(iov_len != PAGE_SIZE && sent + iov_len < total_len);

		if (sent + iov_len > total_len)
			iov_len = total_len - sent;
		err = rpc_pack(desc, 0, msg->msg_iov[i].iov_base, iov_len);
		if (err)
			break;
	}

	return err;
}

static
int
send_iov(struct rpc_desc *desc, struct msghdr *msg, int total_len, int flags)
{
	int err;

	err = rpc_pack_type(desc, total_len);
	if (err)
		return err;

	if (flags & MSG_HDR_ONLY)
		return err;

	if (flags & MSG_USER)
		err = send_user_iov(desc, msg, total_len);
	else
		err = send_kernel_iov(desc, msg, total_len);

	return err;
}

static
int recv_user_iov(struct rpc_desc *desc, struct msghdr *msg, int total_len)
{
	void *page;
	void __user *iov_base;
	int i, iov_len, iov_offset, page_offset, max_page_offset, rcvd, err = 0;

	page = (void *)__get_free_page(GFP_KERNEL);
	if (!page)
		return -ENOMEM;

	i = 0;
	iov_offset = 0;
	for (rcvd = 0; rcvd < total_len; rcvd += PAGE_SIZE) {
		max_page_offset = PAGE_SIZE;
		if (rcvd + max_page_offset > total_len)
			max_page_offset = total_len - rcvd;

		err = rpc_unpack(desc, 0, page, max_page_offset);
		if (err) {
			if (err > 0)
				err = -EPIPE;
			break;
		}

		page_offset = 0;
		while (page_offset < max_page_offset) {
			BUG_ON(i >= msg->msg_iovlen);

			iov_base = (__force void __user *)msg->msg_iov[i].iov_base
				+ iov_offset;
			iov_len = msg->msg_iov[i].iov_len - iov_offset;

			if (iov_len > max_page_offset - page_offset) {
				iov_len = max_page_offset - page_offset;
				iov_offset += iov_len;
			} else {
				i++;
				iov_offset = 0;
			}

			if (copy_to_user(iov_base, page + page_offset,
					 iov_len)) {
				err = -EFAULT;
				goto out_free;
			}

			page_offset += iov_len;
		}
	}

out_free:
	free_page((unsigned long)page);

	return err;
}

static
int recv_kernel_iov(struct rpc_desc *desc, struct msghdr *msg, int total_len)
{
	int iov_len, i, rcvd, err = 0;

	/* FAF server is supposed to have page-backed iovecs */
	for (rcvd = 0, i = 0; rcvd < total_len; rcvd += PAGE_SIZE, i++) {
		BUG_ON(i >= msg->msg_iovlen);

		iov_len = msg->msg_iov[i].iov_len;
		BUG_ON(iov_len != PAGE_SIZE && rcvd + iov_len < total_len);

		if (rcvd + iov_len > total_len)
			iov_len = total_len - rcvd;
		err = rpc_unpack(desc, 0, msg->msg_iov[i].iov_base, iov_len);
		if (err) {
			if (err > 0)
				err = -EPIPE;
			break;
		}
	}

	return err;
}

static int alloc_iov(struct msghdr *msg, int total_len)
{
	struct iovec *iov;
	int i, iovlen;

	iovlen = DIV_ROUND_UP(total_len, PAGE_SIZE);
	iov = kmalloc(sizeof(*iov) * iovlen, GFP_KERNEL);
	if (!iov)
		return -ENOMEM;

	msg->msg_iov = iov;
	msg->msg_iovlen = iovlen;

	if (!iovlen)
		return 0;

	for (i = 0; i < iovlen; i++) {
		iov[i].iov_base = (void *)__get_free_page(GFP_KERNEL);
		if (!iov[i].iov_base)
			goto out_free;
		iov[i].iov_len = PAGE_SIZE;
	}
	iov[iovlen - 1].iov_len = total_len - (iovlen - 1) * PAGE_SIZE;

	return 0;

out_free:
	for (i--; i >= 0; i--)
		free_page((unsigned long)iov[i].iov_base);
	kfree(iov);
	return -ENOMEM;
}

static void free_iov(struct msghdr *msg)
{
	int i;

	for (i = 0; i < msg->msg_iovlen; i++)
		free_page((unsigned long)msg->msg_iov[i].iov_base);
	kfree(msg->msg_iov);
}

static int recv_iov(struct rpc_desc *desc, struct msghdr *msg, int flags)
{
	int total_len, err;

	err = rpc_unpack_type(desc, total_len);
	if (err) {
		if (err > 0)
			err = -EPIPE;
		return err;
	}

	if (!(flags & MSG_USER)) {
		err = alloc_iov(msg, total_len);
		if (err)
			return err;
	}

	if (flags & MSG_HDR_ONLY)
		return err;

	if (flags & MSG_USER) {
		err = recv_user_iov(desc, msg, total_len);
	} else {
		err = recv_kernel_iov(desc, msg, total_len);
		if (err)
			free_iov(msg);
	}

	return err;
}

int send_msghdr(struct rpc_desc* desc,
		struct msghdr *msghdr,
		int total_len,
		int flags)
{
	int err;

	err = rpc_pack(desc, 0, msghdr, sizeof(*msghdr));
	if (err)
		return err;
	if (!(flags & MSG_HDR_ONLY)) {
		err = rpc_pack(desc, 0, msghdr->msg_name, msghdr->msg_namelen);
		if (err)
			return err;
		err = rpc_pack(desc, 0, msghdr->msg_control, msghdr->msg_controllen);
		if (err)
			return err;
	}

	return send_iov(desc, msghdr, total_len, flags);
}

int recv_msghdr(struct rpc_desc* desc,
		struct msghdr *msghdr,
		int flags)
{
	struct msghdr tmp_msg;
	struct msghdr *msg = (flags & MSG_USER) ? &tmp_msg : msghdr;
	int err;

	BUG_ON((flags & MSG_USER) && (flags & MSG_HDR_ONLY));

	err = rpc_unpack(desc, 0, msg, sizeof(*msg));
	if (err)
		goto out_err;

	err = -ENOMEM;
	if (flags & MSG_USER) {
		msg->msg_name = msghdr->msg_name;
	} else {
		msg->msg_name = kmalloc(msg->msg_namelen, GFP_KERNEL);
		if (!msg->msg_name)
			goto out_err;
	}

	/*
	 * FAF server always wants to allocate buffers,
	 * and FAF client always wants to receive data.
	 */
	msg->msg_control = kmalloc(msg->msg_controllen, GFP_KERNEL);
	if (!msg->msg_control)
		goto err_free_name;

	if (!(flags & MSG_HDR_ONLY)) {
		err = rpc_unpack(desc, 0, msg->msg_name, msg->msg_namelen);
		if (err)
			goto err_free_control;
		err = rpc_unpack(desc, 0, msg->msg_control, msg->msg_controllen);
		if (err)
			goto err_free_control;
	}

	if (flags & MSG_USER) {
		if (msg->msg_namelen < msghdr->msg_namelen)
			msghdr->msg_namelen = msg->msg_namelen;

		if (msg->msg_controllen < msghdr->msg_controllen)
			msghdr->msg_controllen = msg->msg_controllen;
		if (copy_to_user(msghdr->msg_control, msg->msg_control,
				 msghdr->msg_controllen)) {
			err = -EFAULT;
			goto err_free_control;
		}

		msg->msg_iov = msghdr->msg_iov;
		msg->msg_iovlen = msghdr->msg_iovlen;
	}

	err = recv_iov(desc, msg, flags);
	if (err)
		goto err_free_control;

	if (flags & MSG_USER) {
		kfree(msg->msg_control);

		msghdr->msg_flags = msg->msg_flags;
	}

	return 0;

err_free_control:
	kfree(msg->msg_control);
err_free_name:
	if (!(flags & MSG_USER))
		kfree(msg->msg_name);
out_err:
	if (err > 0)
		err = -EPIPE;
	return err;
}

void free_msghdr(struct msghdr *msghdr)
{
	kfree(msghdr->msg_name);
	kfree(msghdr->msg_control);

	free_iov(msghdr);
}
