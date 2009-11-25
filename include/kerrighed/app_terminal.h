/*
 * Application management of (pseudo-)terminal
 *  @author Matthieu Fertré
 */

#ifndef __APPLICATION_TERMINAL_H__
#define __APPLICATION_TERMINAL_H__

#include <linux/file.h>
#include "application.h"

/*--------------------------------------------------------------------------*/

struct file *get_valid_terminal(void);

void app_set_checkpoint_terminal(struct app_struct *app,
				 struct file *stdfile);

struct file *app_get_restart_terminal(struct app_struct *app);

void app_put_terminal(struct app_struct *app);

int send_terminal_desc(struct rpc_desc *desc, struct file *tty);

int rcv_terminal_desc(struct rpc_desc *desc, struct app_struct *app);

int send_terminal_id(struct rpc_desc *desc, struct app_struct *app);

int rcv_terminal_id(struct rpc_desc *desc, krgnodemask_t nodes,
		    int *one_terminal);

#endif
