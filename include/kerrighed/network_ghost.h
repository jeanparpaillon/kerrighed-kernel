/** Network ghost interface
 *  @file network_ghost.h
 *
 *  Definition of network ghost structures and functions.
 *  @author Renaud Lottiaux
 */

#ifndef __NETWORK_GHOST_H__
#define __NETWORK_GHOST_H__

#include <kerrighed/ghost_types.h>

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                  TYPES                                   *
 *                                                                          *
 *--------------------------------------------------------------------------*/

struct rpc_desc;

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/

/** Create a network file ghost.
 *  @author Renaud Lottiaux
 *
 *  @param  access Ghost access (READ/WRITE)
 *  @param  desc   RPC descriptor to send/receive data on.
 *
 *  @return        0 if everything ok
 *                 Negative value otherwise.
 */
ghost_t * create_network_ghost(int access, struct rpc_desc *desc);

#endif /* __NETWORK_GHOST_H__ */
