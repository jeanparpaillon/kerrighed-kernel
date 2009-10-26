/** Kerrighed Open File Access Forwarding System.
 *  @file faf_internal.h
 *
 *  @author Renaud Lottiaux
 */

#ifndef __FAF__
#define __FAF__

#include <linux/wait.h>
#include <kerrighed/faf.h>

struct epm_action;
struct dvfs_file_struct;

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                 MACROS                                   *
 *                                                                          *
 *--------------------------------------------------------------------------*/

#define FAF_HASH_TABLE_SIZE 1024

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                  TYPES                                   *
 *                                                                          *
 *--------------------------------------------------------------------------*/

typedef struct faf_client_data {
	kerrighed_node_t server_id;
	int server_fd;
	unsigned long f_flags;
	fmode_t f_mode;
	loff_t f_pos;
	wait_queue_head_t poll_wq;
	unsigned int poll_revents;
	umode_t i_mode;
} faf_client_data_t;

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/

void faf_init (void);
void faf_finalize (void);

void check_activate_faf (struct task_struct *tsk, int index, struct file *file,
			 struct epm_action *action);

void check_last_faf_client_close(struct file *file,
				 struct dvfs_file_struct *dvfs_file);
void check_close_faf_srv_file(struct file *file);
void free_faf_file_private_data(struct file *file);

#endif // __FAF__
