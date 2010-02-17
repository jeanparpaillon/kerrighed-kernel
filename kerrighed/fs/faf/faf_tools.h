/** Kerrighed FAF tools.
 *  @file faf_tools.h
 *  
 *  @author Pascal Gallard
 */

#ifndef __FAF_TOOLS__
#define __FAF_TOOLS__


int send_msghdr(struct rpc_desc* desc, struct msghdr *msghdr, int from_user, int ctl_from_user) ;

int recv_msghdr(struct rpc_desc* desc, struct msghdr *msghdr, int to_user) ;

int free_msghdr(struct msghdr *msghdr) ;


#endif // __FAF_TOOLS__
