#ifndef __RUACCESS_H__
#define __RUACCESS_H__

struct rpc_desc;

int prepare_ruaccess(struct rpc_desc *desc);
int cleanup_ruaccess(struct rpc_desc *desc);

int handle_ruaccess(struct rpc_desc *desc);

#endif /* __RUACCESS_H__ */
