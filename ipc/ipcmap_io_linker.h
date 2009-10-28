/** KDDM IPC allocation bitmap Linker.
 *  @file ipcmap_io_linker.h
 *
 *  Manage a distributed allocation bitmap for IPC ids.
 *  @author Renaud Lottiaux
 */

#ifndef __IPCMAP_IO_LINKER__
#define __IPCMAP_IO_LINKER__

extern struct kmem_cache *ipcmap_object_cachep;



/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                  TYPES                                   *
 *                                                                          *
 *--------------------------------------------------------------------------*/


typedef struct ipcmap_object {
	unsigned long alloc_map;
} ipcmap_object_t;


extern struct iolinker_struct ipcmap_linker;


#endif
