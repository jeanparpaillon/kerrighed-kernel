/** Object server.
 *  @file object_server.h
 *
 *  Definition of the object server interface.
 *  @author Renaud Lottiaux
 */

#ifndef __OBJECT_SERVER__
#define __OBJECT_SERVER__

#include <kddm/io_linker.h>



/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                 MACROS                                   *
 *                                                                          *
 *--------------------------------------------------------------------------*/



#define NODE_MEM_FREE 1
#define NODE_MEM_FULL 2


#define KDDM_OBJ_COPY_ON_READ  0x00000001
#define KDDM_OBJ_COPY_ON_WRITE 0x00000002
#define KDDM_ASYNC_REQ         0x00000004
#define KDDM_NO_FT_REQ         0x00000008
#define KDDM_SEND_OWNERSHIP    0x00000010
#define KDDM_DONT_KILL         0x00000020
#define KDDM_NEED_OBJ_RM_ACK2  0x00000040
#define KDDM_NO_FREEZE         0x00000080
#define KDDM_IO_FLUSH          0x00000100
#define KDDM_SYNC_OBJECT       0x00000200
#define KDDM_NO_DATA           0x00000400
#define KDDM_TRY_GRAB          0x00000800
#define KDDM_REMOVE_ON_ACK     0x00001000
#define KDDM_COW_OBJECT        0x00002000

#define KDDM_SET_REQ_TYPE (KDDM_OBJ_COPY_ON_READ | KDDM_OBJ_COPY_ON_WRITE)



/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                  TYPES                                   *
 *                                                                          *
 *--------------------------------------------------------------------------*/

#define MSG_HEADER \
	kddm_set_id_t set_id;        /**< Set identifier. */ \
	int ns_id;                   /**< Name space identifier */ \
	objid_t objid;               /**< Object id */ \
	long req_id;                 /**< USED FOR DEBUGGING */


/** Structure used to store data sent to the object server. */
/** WARNING: in this structure, field order matter */
typedef struct {
	MSG_HEADER
	int request_type;
	int flags;                   /**< No First Touch request ? */
	kerrighed_node_t reply_node; /**< Identifier of the requesting node */
	kerrighed_node_t new_owner;  /**< Identifier of the new object owner */
	kerrighed_node_t sender_probe_owner;
} msg_server_t;

/** WARNING: in this structure, field order matter */
typedef struct {
	MSG_HEADER
	krgnodemask_t rmset;              /**< The remove set to wait for */
} rm_done_msg_server_t;

/** Structure used to store data sent for object ownership change. */
/** WARNING: in this structure, field order matter */
typedef struct {
	MSG_HEADER
	kerrighed_node_t reply_node; /**< Identifier of the requesting node */
	masterObj_t owner_info;      /**< Object owner information */
} msg_injection_t;


/** Structure used to store data sent to the object server. */
/** WARNING: in this structure, field order matter */
typedef struct {
	MSG_HEADER
	kddm_obj_state_t object_state; /**< State of the received object */
	int flags;                     /**< Falgs : synchro, ... */
} msg_object_receiver_t;



/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/


/** Object Server Initialisation.
 *  @author Renaud Lottiaux
 *
 *  Launch the Object Server handler thread.
 */
void object_server_init (void);

/** Object Server Finalization.
 *  @author Renaud Lottiaux
 *
 *  Kill the Object Server handler thread.
 */
void object_server_finalize (void);


#endif
