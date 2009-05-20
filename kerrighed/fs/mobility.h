/** DVFS mobililty interface
 *  @file mobility.h
 *
 *  Definition of DVFS mobility function interface.
 *  @author Renaud Lottiaux
 */

#ifndef __MOBILITY_H__
#define __MOBILITY_H__

#include <kerrighed/ghost_types.h>

struct epm_action;

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                   MACROS                                 *
 *                                                                          *
 *--------------------------------------------------------------------------*/
#define MAX_DVFS_MOBILITY_OPS 16

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                  TYPES                                   *
 *                                                                          *
 *--------------------------------------------------------------------------*/

struct dvfs_mobility_operations {
  int (*file_export) (struct epm_action *,
		      ghost_t *, struct task_struct *, int, struct file *);
  int (*file_import) (struct epm_action *,
		      ghost_t *, struct task_struct *, struct file **);
};

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                            EXTERN VARIABLES                              *
 *                                                                          *
 *--------------------------------------------------------------------------*/

extern struct dvfs_mobility_operations *dvfs_mobility_ops[];

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/

static inline int dvfs_mobility_index (unsigned short mode)
{
	return (mode & S_IFMT) >> 12;
}

static inline void register_dvfs_mobility_ops (unsigned short mode,
					       struct dvfs_mobility_operations *ops)
{
	int index = dvfs_mobility_index (mode);

	if (index < 0 || index >= MAX_DVFS_MOBILITY_OPS) {
		printk ("Invalid index : %d\n", index);
		BUG();
	}
	else
		dvfs_mobility_ops[index] = ops;
}

static inline struct dvfs_mobility_operations *get_dvfs_mobility_ops (
	unsigned short mode)
{
	int index = dvfs_mobility_index (mode);

	if (index < 0 || index >= MAX_DVFS_MOBILITY_OPS)
		return NULL;
	else
		return dvfs_mobility_ops[index];
}

int dvfs_mobility_init(void) ;

void dvfs_mobility_finalize (void) ;

#endif // __MOBILITY_H__
