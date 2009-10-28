/** KDDM SHM Memory Linker.
 *  @file shm_memory_linker.h
 *
 *  Link KDDM and Linux SHM memory system.
 *  @author Renaud Lottiaux
 */

#ifndef __SHM_MEMORY_LINKER__
#define __SHM_MEMORY_LINKER__


/*--------------------------------------------------------------------------*
 *                                                                          *
 *                            EXTERN VARIABLES                              *
 *                                                                          *
 *--------------------------------------------------------------------------*/

extern struct vm_operations_struct _krg_shmem_vmops;
extern struct file_operations krg_shm_file_operations;

#endif
