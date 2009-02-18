/** Unique id generator
 *  @file unique_id.c
 *
 *  Implementation of unique id generator. This mechanism generates
 *  locally, an indentifier which is unique in the cluster.
 *
 *  Copyright (C) 2006-2007, Renaud Lottiaux, Kerlabs.
 */

#include <linux/hardirq.h>
#include <linux/module.h>
#include <linux/unique_id.h>
#include <kerrighed/krginit.h>

#define INITVAL 1

unique_id_root_t mm_unique_id_root = {
	.local_unique_id = ATOMIC_LONG_INIT(INITVAL),
};

/** Initialize a unique id root.
 *  @author Renaud Lottiaux
 *
 *  @param root   The root to initialize
 *  @return       0 if everything ok.
 *                Negative value otherwise.
 */
int init_unique_id_root(unique_id_root_t *root)
{
	/* Value 0 is reserved for UNIQUE_ID_NONE */

	atomic_long_set (&root->local_unique_id, INITVAL);

	return 0;
}
EXPORT_SYMBOL(init_unique_id_root);



/** Initialize a unique id root with a given init value.
 *  @author Renaud Lottiaux
 *
 *  @param root   The root to initialize
 *  @param base   Init of value for the key generator.
 *  @return       0 if everything ok.
 *                Negative value otherwise.
 */
int init_and_set_unique_id_root(unique_id_root_t *root, int base)
{
	atomic_long_set (&root->local_unique_id, base + INITVAL);

	return 0;
}
EXPORT_SYMBOL(init_and_set_unique_id_root);



/** Generate a unique id from a given root.
 *  @author Renaud Lottiaux
 *
 *  @param root   The root of the unique id to generate.
 *  @return       A unique id !
 */
unique_id_t get_unique_id(unique_id_root_t *root)
{
	unique_id_t unique_id ;

	/* If the unique ID root has not been initialized... */
	if (atomic_long_read(&root->local_unique_id) == 0)
		return UNIQUE_ID_NONE;

	unique_id = atomic_long_inc_return (&root->local_unique_id);

	/* Check if there is a loop in the identitier generator */

	if ((unique_id & UNIQUE_ID_LOCAL_MASK) == 0)
		panic ("Unique id generator loop !\n");

	/* Combine local unique id and local node id to generate a
	   identifier which is unique cluster wide */

	unique_id = unique_id | ((unsigned long)kerrighed_node_id << UNIQUE_ID_NODE_SHIFT);

	return unique_id;
}
EXPORT_SYMBOL(get_unique_id);


void init_unique_ids(void)
{
	init_unique_id_root(&mm_unique_id_root);
}
