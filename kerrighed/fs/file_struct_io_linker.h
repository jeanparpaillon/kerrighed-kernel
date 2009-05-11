/** DVFS level 3 - File Struct Linker.
 *  @file file_struct_io_linker.h
 *
 *  @author Renaud Lottiaux
 */

#ifndef __DVFS_FILE_STRUCT_LINKER__
#define __DVFS_FILE_STRUCT_LINKER__

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                            EXTERN VARIABLES                              *
 *                                                                          *
 *--------------------------------------------------------------------------*/

extern struct iolinker_struct dvfs_file_struct_io_linker;
extern struct kmem_cache *dvfs_file_cachep;

#endif // __FILE_STRUCT_LINKER__
