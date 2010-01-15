#ifndef __REMOTE_SLEEP_H__
#define __REMOTE_SLEEP_H__

#include <linux/types.h>

struct rpc_desc;

int remote_sleep_prepare(struct rpc_desc *desc);
void remote_sleep_finish(void);

int unpack_remote_sleep_res_prepare(struct rpc_desc *desc);
int unpack_remote_sleep_res(struct rpc_desc *desc, void *res, size_t size);

#define unpack_remote_sleep_res_type(desc, v) \
	unpack_remote_sleep_res(desc, &v, sizeof(v))

#endif /* __REMOTE_SLEEP_H__ */
