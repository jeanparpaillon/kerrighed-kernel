/** Unique id generator interface
 *  @file unique_id.h
 *
 *  Definition of unique id generator interface. This mechanism generates
 *  locally, an indentifier which is unique in the cluster.
 *  @author Renaud Lottiaux
 */

#ifndef __UNIQUE_ID_H__
#define __UNIQUE_ID_H__


#include <linux/spinlock.h>
#include <kerrighed/types.h>



/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                 MACROS                                   *
 *                                                                          *
 *--------------------------------------------------------------------------*/



#define UNIQUE_ID_NONE 0UL          /* Invalid unique id */

#if BITS_PER_LONG == 64
#define UNIQUE_ID_LOCAL_BITS 56
#else
#define UNIQUE_ID_LOCAL_BITS 24
#endif

#define UNIQUE_ID_NODE_BITS 8     /* Number of bits used for nodeid part of
				       the unique id. */

#define UNIQUE_ID_NODE_SHIFT (UNIQUE_ID_LOCAL_BITS)
#define UNIQUE_ID_LOCAL_MASK ((1UL << UNIQUE_ID_LOCAL_BITS) - 1)



/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                  TYPES                                   *
 *                                                                          *
 *--------------------------------------------------------------------------*/



/** Unique id root type
 */
typedef struct unique_id_root {
	atomic_long_t local_unique_id;   /**< Local unique id */
} unique_id_root_t;


/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN VARIABLES                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/



extern unique_id_root_t mm_unique_id_root;



/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/



/** Initialize a unique id root.
 *  @author Renaud Lottiaux
 *
 *  @param root   The root to initialize
 *  @return       0 if everything ok.
 *                Negative value otherwise.
 */
int init_unique_id_root(unique_id_root_t *root);



/** Initialize a unique id root with a given init value.
 *  @author Renaud Lottiaux
 *
 *  @param root   The root to initialize
 *  @param base   Base value for the key generator.
 *  @return       0 if everything ok.
 *                Negative value otherwise.
 */
int init_and_set_unique_id_root(unique_id_root_t *root, int base);



/** Generate a unique id from a given root.
 *  @author Renaud Lottiaux
 *
 *  @param root   The root of the unique id to generate.
 *  @return       A unique id !
 */
unique_id_t get_unique_id(unique_id_root_t *unique_id_root);


void init_unique_ids(void);

#endif // __UNIQUE_ID_H__
