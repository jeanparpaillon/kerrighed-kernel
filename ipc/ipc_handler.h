/** Interface of IPC management.
 *  @file ipc_handler.h
 *
 *  @author Renaud Lottiaux, Matthieu Fertré
 */


#ifndef IPC_HANDLER_H
#define IPC_HANDLER_H

#include <linux/ipc.h>
#include <linux/ipc_namespace.h>

int krg_ipc_get_maxid(struct ipc_ids *ids);
int krg_ipc_get_new_id(struct ipc_ids *ids);
void krg_ipc_rmid(struct ipc_ids *ids, int index);
int krg_ipc_get_this_id(struct ipc_ids *ids, int id);

struct ipc_namespace *find_get_krg_ipcns(void);

int ipc_hotplug_init(void);
void ipc_hotplug_cleanup(void);

void ipc_handler_finalize (void);
void ipc_handler_init (void);

#endif // IPC_HANDLER_H
