/** Global management of faf files interface.
 *  @file faf_file_mgr.h
 *
 *  @author Renaud Lottiaux
 */
#ifndef __FAF_FILE_MGR__
#define __FAF_FILE_MGR__

#include <kerrighed/action.h>
#include <kerrighed/ghost.h>

struct rpc_desc;

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                            EXTERN VARIABLES                              *
 *                                                                          *
 *--------------------------------------------------------------------------*/

extern struct dvfs_mobility_operations dvfs_mobility_faf_ops;
extern struct kmem_cache *faf_client_data_cachep;

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/

struct file *create_faf_file_from_krg_desc(struct task_struct *task,
					   void *_desc);

int get_faf_file_krg_desc(struct file *file, void **desc, int *desc_size);

/* file will be faffed if not already */
int send_faf_file_desc(struct rpc_desc *desc, struct file *file);

/* file must be already faffed */
int __send_faf_file_desc(struct rpc_desc *desc, struct file *file);

struct file *rcv_faf_file_desc(struct rpc_desc *desc);

#endif // __FAF_FILE_MGR__
