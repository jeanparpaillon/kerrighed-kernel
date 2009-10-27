/** Main kerrighed types.
 *  @file gtypes.h
 *
 *  Definition of the main types and structures.
 *  @author Renaud Lottiaux
 */

#ifndef __KERRIGHED_TYPES__
#define __KERRIGHED_TYPES__

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                 MACROS                                   *
 *                                                                          *
 *--------------------------------------------------------------------------*/

#ifdef CONFIG_KRG_AUTONODEID
#define NR_BITS_IN_MAX_NODE_ID     8
#else
#define NR_BITS_IN_MAX_NODE_ID     7
#endif

#define KERRIGHED_MAX_NODES      (1<<NR_BITS_IN_MAX_NODE_ID)        /* Real limit 32766 */
#define KERRIGHED_HARD_MAX_NODES 256

#define KERRIGHED_MAX_CLUSTERS   256
#define KERRIGHED_NODE_ID_NONE    -1        /* Invalid node id */

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                  TYPES                                   *
 *                                                                          *
 *--------------------------------------------------------------------------*/

#ifndef __ASSEMBLER__

/** Type for node id           */
typedef short kerrighed_node_t;

/** Event counter type */
typedef unsigned long event_counter_t;

/** Physical address type */
typedef unsigned long physaddr_t;

/** Network id */
typedef unsigned int kerrighed_network_t;

enum kerrighed_status {
	KRG_FIRST_START,
	KRG_FINAL_STOP,
	KRG_NODE_STARTING,
	KRG_NODE_STOPING,
	KRG_RUNNING_CLUSTER,
};
typedef enum kerrighed_status kerrighed_status_t;

#endif /* __ASSEMBLER__ */

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                             EXTERN VARIABLES                             *
 *                                                                          *
 *--------------------------------------------------------------------------*/

#endif /* __KERRIGHED_TYPES__ */
