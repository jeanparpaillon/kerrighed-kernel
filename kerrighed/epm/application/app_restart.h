/** Application restart
 *  @author Matthieu Fertré
 */

#ifndef __APPLICATION_RESTART_H__
#define __APPLICATION_RESTART_H__

int app_restart(struct restart_request *req,
		const task_identity_t *requester);

void application_restart_rpc_init(void);

#endif /* __APPLICATION_RESTART_H__ */
