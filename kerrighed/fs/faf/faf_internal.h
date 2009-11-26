/** Kerrighed Open File Access Forwarding System.
 *  @file faf_internal.h
 *
 *  @author Renaud Lottiaux
 */

#ifndef __FAF__
#define __FAF__

#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/rwsem.h>
#include <linux/wait.h>
#include <kerrighed/faf.h>
#include <kerrighed/sys/types.h>

struct epm_action;
struct dvfs_file_struct;
struct remote_sleepers_queue;
struct hotplug_context;

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                 MACROS                                   *
 *                                                                          *
 *--------------------------------------------------------------------------*/

#define FAF_HASH_TABLE_SIZE 1024

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN VARIABLES                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/

extern struct remote_sleepers_queue faf_remote_sleepers;
extern struct list_head faf_client_list[KERRIGHED_MAX_NODES];
extern spinlock_t faf_client_list_lock[KERRIGHED_MAX_NODES];
extern struct rw_semaphore faf_client_sem[KERRIGHED_MAX_NODES];
extern struct rw_semaphore faf_srv_hotplug_rwsem;

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/

void faf_init (void);
void faf_finalize (void);
void faf_hotplug_init(void);
void faf_polled_fd_remove_local(void);
int faf_remove_local(struct hotplug_context *ctx);

int check_activate_faf(struct task_struct *tsk, int index, struct file *file,
		       struct epm_action *action);

void check_last_faf_client_close(struct file *file,
				 struct dvfs_file_struct *dvfs_file);
void __check_close_faf_srv_file(unsigned long objid, struct file *file);
void check_close_faf_srv_file(struct file *file);
void check_close_faf_srv_files(void);
void free_faf_file_private_data(struct file *file);

bool faf_srv_hold(struct faf_client_data *data);
void faf_srv_release(struct faf_client_data *data);

#endif // __FAF__
