/** KDDM SEM Array Linker.
 *  @file semarray_io_linker.h
 *
 *  Link KDDM and Linux SEM Array mechanisms.
 *  @author Matthieu Fertré
 */

#ifndef __SEMARRAY_IO_LINKER__
#define __SEMARRAY_IO_LINKER__

#include <kddm/kddm_types.h>

extern struct kmem_cache *semarray_object_cachep;

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                  TYPES                                   *
 *                                                                          *
 *--------------------------------------------------------------------------*/


typedef struct semarray_object {
	struct sem_array imported_sem;
	struct sem_array *local_sem;
	struct sem* mobile_sem_base;
} semarray_object_t;


extern struct iolinker_struct semarray_linker;
extern struct iolinker_struct semkey_linker;

#define remote_sleeper_pid(q) ((pid_t)((long)(q->sleeper)))

#endif
