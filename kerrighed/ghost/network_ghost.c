/** Network Ghost interface.
 *  @file network_ghost.c
 *
 *  Copyright (C) 2001-2006, INRIA, Universite de Rennes 1, EDF.
 *  Copyright (C) 2007-2008, Louis Rilling - Kerlabs.
 */
#include <net/krgrpc/rpc.h>
#include <kerrighed/ghost.h>
#include <kerrighed/network_ghost.h>

/** Read data from a network ghost.
 *  @author Renaud Lottiaux, Geoffroy Vallée
 *
 *  @param  ghost   Ghost to read data from.
 *  @param  buff    Buffer to store data.
 *  @param  length  Size of data to read.
 *
 *  @return        0 if everything ok
 *                 Negative value otherwise.
 */
int network_ghost_read(struct ghost *ghost, void *buff, size_t length)
{
	struct rpc_desc *desc = ghost->data;
	int retval;

	retval = rpc_unpack(desc, 0, buff, length);

	return retval;
}

/** Write data to a network ghost.
 *  @author Renaud Lottiaux, Geoffroy Vallée
 *
 *  @param  ghost   Ghost to write data to.
 *  @param  buff    Buffer to write in the ghost.
 *  @param  length  Size of data to write.
 *
 *  @return        0 if everything ok
 *                 Negative value otherwise.
 */
int network_ghost_write(struct ghost *ghost, const void *buff, size_t length)
{
	struct rpc_desc *desc = ghost->data;
	int retval;

	retval = rpc_pack(desc, 0, buff, length);

	return retval;
}

/** Close a network ghost.
 *  @author Matthieu Fertré
 *
 *  @param  ghost   Ghost to close.
 *
 *  @return        0 if everything ok
 *                 Negative value otherwise.
 */
int network_ghost_close(struct ghost *ghost)
{
	ghost->data = NULL;
	free_ghost(ghost);
	return 0;
}

/** Netwotk ghost operations
 */
struct ghost_operations ghost_network_ops = {
	.read  = network_ghost_read,
	.write = network_ghost_write,
	.close = network_ghost_close
};

/** Create a network ghost.
 *  @author Renaud Lottiaux
 *
 *  @param  access Ghost access (READ/WRITE)
 *  @param  desc   RPC descriptor to send/receive on.
 *
 *  @return        0 if everything ok
 *                 Negative value otherwise.
 */
ghost_t * create_network_ghost(int access, struct rpc_desc *desc)
{
	struct ghost *ghost;

	/* A network ghost can be used in bi-directional mode */
	BUG_ON(!access);

	ghost = create_ghost(GHOST_NETWORK, access);
	if (IS_ERR(ghost))
		return ghost;

	ghost->data = desc;
	ghost->ops = &ghost_network_ops;

	return ghost;
}
