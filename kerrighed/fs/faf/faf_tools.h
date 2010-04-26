/** Kerrighed FAF tools.
 *  @file faf_tools.h
 *  
 *  @author Pascal Gallard
 */

#ifndef __FAF_TOOLS__
#define __FAF_TOOLS__

enum {
	MSG_USER     = 1,
	MSG_HDR_ONLY = 2,
};

int
send_iov(struct rpc_desc *desc, struct iovec *iov, int iovcnt, size_t total_len, int flags);
int recv_iov(struct rpc_desc *desc, struct iovec *iov, int iovcnt, size_t total_len, int flags);
int alloc_iov(struct iovec **iov, int *iovcnt, size_t total_len);
void free_iov(struct iovec *iov, int iovcnt);

int send_msghdr(struct rpc_desc *desc, struct msghdr *msghdr,
		size_t total_len, int flags);
int recv_msghdr(struct rpc_desc *desc, struct msghdr *msghdr, size_t total_len, int flags);
void free_msghdr(struct msghdr *msghdr);

#endif // __FAF_TOOLS__
