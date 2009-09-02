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

void msg_handler_init(void);
void msg_handler_finalize(void);

#endif // MSG_HANDLER_H
