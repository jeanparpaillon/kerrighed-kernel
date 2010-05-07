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
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/

void faf_init (void);
void faf_finalize (void);

int check_activate_faf(struct task_struct *tsk, int index, struct file *file,
		       struct epm_action *action);

void check_last_faf_client_close(struct file *file,
				 struct dvfs_file_struct *dvfs_file);
void check_close_faf_srv_file(struct file *file);
void free_faf_file_private_data(struct file *file);

#endif // __FAF__
