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
int send_user_iov(struct rpc_desc *desc, struct iovec *iov, int iovcnt, size_t total_len)
{
	void *page;
	void __user *iov_base;
	size_t iov_len, iov_offset, sent;
	int i, page_offset, max_page_offset, err = 0;

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
			BUG_ON(i >= iovcnt);

			iov_base = (__force void __user *)iov[i].iov_base
				+ iov_offset;
			iov_len = iov[i].iov_len - iov_offset;

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
int send_kernel_iov(struct rpc_desc *desc, struct iovec *iov, int iovcnt, size_t total_len)
{
	size_t iov_len, sent;
	int i, err = 0;

	/* FAF server is supposed to have page-backed iovecs */
	for (sent = 0, i = 0; sent < total_len; sent += PAGE_SIZE, i++) {
		BUG_ON(i >= iovcnt);

		iov_len = iov[i].iov_len;
		BUG_ON(iov_len != PAGE_SIZE && sent + iov_len < total_len);

		if (sent + iov_len > total_len)
			iov_len = total_len - sent;
		err = rpc_pack(desc, 0, iov[i].iov_base, iov_len);
		if (err)
			break;
	}

	return err;
}

int
send_iov(struct rpc_desc *desc, struct iovec *iov, int iovcnt, size_t total_len, int flags)
{
	int err;

	if (flags & MSG_USER)
		err = send_user_iov(desc, iov, iovcnt, total_len);
	else
		err = send_kernel_iov(desc, iov, iovcnt, total_len);

	return err;
}

static
int recv_user_iov(struct rpc_desc *desc, struct iovec *iov, int iovcnt, size_t total_len)
{
	void *page;
	void __user *iov_base;
	size_t iov_len, iov_offset, rcvd;
	int i, page_offset, max_page_offset, err = 0;

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
			BUG_ON(i >= iovcnt);

			iov_base = (__force void __user *)iov[i].iov_base
				+ iov_offset;
			iov_len = iov[i].iov_len - iov_offset;

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
int recv_kernel_iov(struct rpc_desc *desc, struct iovec *iov, int iovcnt, size_t total_len)
{
	size_t iov_len, rcvd;
	int i, err = 0;

	/* FAF server is supposed to have page-backed iovecs */
	for (rcvd = 0, i = 0; rcvd < total_len; rcvd += PAGE_SIZE, i++) {
		BUG_ON(i >= iovcnt);

		iov_len = iov[i].iov_len;
		BUG_ON(iov_len != PAGE_SIZE && rcvd + iov_len < total_len);

		if (rcvd + iov_len > total_len)
			iov_len = total_len - rcvd;
		err = rpc_unpack(desc, 0, iov[i].iov_base, iov_len);
		if (err) {
			if (err > 0)
				err = -EPIPE;
			break;
		}
	}

	return err;
}

int alloc_iov(struct iovec **iov, int *iovcnt, size_t total_len)
{
	struct iovec *__iov;
	int i, iovlen;

	iovlen = DIV_ROUND_UP(total_len, PAGE_SIZE);
	__iov = kmalloc(sizeof(*__iov) * iovlen, GFP_KERNEL);
	if (!__iov)
		return -ENOMEM;

	*iov = __iov;
	*iovcnt = iovlen;

	if (!iovlen)
		return 0;

	for (i = 0; i < iovlen; i++) {
		__iov[i].iov_base = (void *)__get_free_page(GFP_KERNEL);
		if (!__iov[i].iov_base)
			goto out_free;
		__iov[i].iov_len = PAGE_SIZE;
	}
	__iov[iovlen - 1].iov_len = total_len - (iovlen - 1) * PAGE_SIZE;

	return 0;

out_free:
	for (i--; i >= 0; i--)
		free_page((unsigned long)__iov[i].iov_base);
	kfree(__iov);
	return -ENOMEM;
}

void free_iov(struct iovec *iov, int iovcnt)
{
	int i;

	for (i = 0; i < iovcnt; i++)
		free_page((unsigned long)iov[i].iov_base);
	kfree(iov);
}

int recv_iov(struct rpc_desc *desc, struct iovec *iov, int iovcnt, size_t total_len, int flags)
{
	int err;

	if (flags & MSG_USER)
		err = recv_user_iov(desc, iov, iovcnt, total_len);
	else
		err = recv_kernel_iov(desc, iov, iovcnt, total_len);

	return err;
}

int send_msghdr(struct rpc_desc* desc,
		struct msghdr *msghdr,
		size_t total_len,
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
		err = send_iov(desc, msghdr->msg_iov, msghdr->msg_iovlen, total_len, flags);
	}

	return err;
}

int recv_msghdr(struct rpc_desc* desc,
		struct msghdr *msghdr,
		size_t total_len,
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

		msg->msg_iov = msghdr->msg_iov;
		msg->msg_iovlen = msghdr->msg_iovlen;
	} else {
		int msg_iovlen;

		msg->msg_name = kmalloc(msg->msg_namelen, GFP_KERNEL);
		if (!msg->msg_name)
			goto out_err;

		err = alloc_iov(&msg->msg_iov, &msg_iovlen, total_len);
		if (err)
			goto err_free_name;
		msg->msg_iovlen = msg_iovlen;
	}

	/*
	 * FAF server always wants to allocate buffers,
	 * and FAF client always wants to receive data.
	 */
	msg->msg_control = kmalloc(msg->msg_controllen, GFP_KERNEL);
	if (!msg->msg_control)
		goto err_free_iov;

	if (!(flags & MSG_HDR_ONLY)) {
		err = rpc_unpack(desc, 0, msg->msg_name, msg->msg_namelen);
		if (err)
			goto err_free_control;
		err = rpc_unpack(desc, 0, msg->msg_control, msg->msg_controllen);
		if (err)
			goto err_free_control;
		err = recv_iov(desc, msg->msg_iov, msg->msg_iovlen, total_len, flags);
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
		kfree(msg->msg_control);

		msghdr->msg_flags = msg->msg_flags;
	}

	return 0;

err_free_control:
	kfree(msg->msg_control);
err_free_iov:
	if (!(flags & MSG_USER))
		free_iov(msg->msg_iov, msg->msg_iovlen);
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

	free_iov(msghdr->msg_iov, msghdr->msg_iovlen);
}
