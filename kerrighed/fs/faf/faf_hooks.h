/** Kerrighed Open File Access Forwarding System.
 *  @file file_forwarding.h
 *
 *  @author Renaud Lottiaux
 */

#ifndef __FAF_HOOKS__
#define __FAF_HOOKS__

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN VARIABLES                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/

extern struct file_operations faf_file_ops;

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/

void faf_hooks_init (void);
void faf_hooks_finalize (void);

#endif // __FAF_HOOKS__
