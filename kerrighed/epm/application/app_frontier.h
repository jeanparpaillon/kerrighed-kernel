/**
 *  Application frontier
 *  @author Matthieu Fertré
 */

#ifndef __APPLICATION_FRONTIER_H__
#define __APPLICATION_FRONTIER_H__

long get_appid_from_pid(pid_t pid);

void application_frontier_rpc_init(void);

#endif /* __APPLICATION_FRONTIER_H__ */
