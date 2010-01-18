/** Interface of IPC msg management.
 *  @file msg_handler.h
 *
 *  @author Matthieu Fertré
 */


#ifndef MSG_HANDLER_H
#define MSG_HANDLER_H

#include <linux/msg.h>

struct kddm_set;

struct kddm_set *krgipc_ops_master_set(struct krgipc_ops *ipcops);

struct remote_sleepers_queue;

extern struct remote_sleepers_queue msg_remote_sleepers;

int krg_msg_flush_set(struct ipc_namespace *ns);

void msg_handler_init(void);
void msg_handler_finalize(void);

#endif // MSG_HANDLER_H
