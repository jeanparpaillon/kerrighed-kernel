/** Ghost management type definition
 *  @file ghost_types.h
 *
 *  Definition of ghost management type.
 *  @author Renaud Lottiaux
 */
#ifndef __GHOST_TYPES__
#define __GHOST_TYPES__

#include <kerrighed/types.h>

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                  TYPES                                   *
 *                                                                          *
 *--------------------------------------------------------------------------*/

enum ghost_access_t {
	__GHOST_READ,
	__GHOST_WRITE
};

#define GHOST_READ (1<<__GHOST_READ)
#define GHOST_WRITE (1<<__GHOST_WRITE)

typedef enum {
	GHOST_NETWORK,
	GHOST_FILE
} ghost_type_t; /**< Ghost type (network, file, etc) */

struct ghost ;

/** Ghost operation structure
 */
typedef struct ghost_operations {
	int (*write) (struct ghost *ghost, const void *buff, size_t length);
	int (*read) (struct ghost *ghost, void *buff, size_t length);
	int (*close) (struct ghost *ghost);
} ghost_operations_t;

/** Ghost structure
 */
typedef struct ghost {
	ghost_type_t type;         /**< Ghost type (network, file, etc */
	size_t size;               /**< Size of data stored in the ghost */
	ghost_operations_t *ops;   /**< Ghost operation (read, write, etc) */
	void *data;                /**< Ghost private data */
	int access;                /**< Kind of access to the ghost (read/write) */
} ghost_t;

#endif // __GHOST_TYPES__
