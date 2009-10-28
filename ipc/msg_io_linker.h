/** KDDM IPC MSG id Linker.
 *  @file msgid_io_linker.h
 *
 *  Link KDDM and Linux IPC msg id mechanisms.
 *  @author Matthieu Fertré
 */

#ifndef __MSGID_IO_LINKER__
#define __MSGID_IO_LINKER__

#include <kddm/kddm_types.h>

extern struct kmem_cache *msq_object_cachep;

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                  TYPES                                   *
 *                                                                          *
 *--------------------------------------------------------------------------*/


typedef struct msq_object {
	struct msg_queue mobile_msq;
	struct msg_queue *local_msq;
} msq_object_t;


extern struct iolinker_struct msq_linker;
extern struct iolinker_struct msqkey_linker;
extern struct iolinker_struct msqmaster_linker;

#endif
