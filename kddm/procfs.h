#ifndef KDDM_PROC_H

#define KDDM_PROC_H

#ifdef __KERNEL__

#include <linux/proc_fs.h>
#include <kerrighed/krg_services.h>
#include <kddm/kddm_types.h>

#endif // __KERNEL__



/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                  TYPES                                   *
 *                                                                          *
 *--------------------------------------------------------------------------*/




/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                 MACROS                                   *
 *                                                                          *
 *--------------------------------------------------------------------------*/



/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/

#ifdef __KERNEL__

int procfs_kddm_init (void);
int procfs_kddm_finalize (void);


/** Create a /proc/kerrighed/kddm/<set_id> directory and sub-directories.
 *  @author Gael Utard, Renaud Lottiaux
 *
 *  @param set_id   Id of the kddm set to create a proc entry for.
 *
 *  @return proc_fs entry created.
 */
struct proc_dir_entry *create_kddm_proc (kddm_set_id_t set_id);



/** Remove a /proc/kerrighed/kddm/<set_id> directory and sub-directories.
 *  @author Renaud Lottiaux
 *
 *  @param proc_entry    Struct of the proc entry to destroy.
 */
void remove_kddm_proc (struct proc_dir_entry *proc_entry);


#endif /* __KERNEL__ */

#endif /* KDDM_PROC_H */
