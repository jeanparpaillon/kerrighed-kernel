/** Ghost interface.
 *  @file ghost_api.c
 *
 *  Copyright (C) 2001-2006, INRIA, Universite de Rennes 1, EDF.
 */

#include <linux/slab.h>
#include <kerrighed/ghost.h>

static struct kmem_cache *ghost_cachep;

/** Create a new ghost struct. */
ghost_t *create_ghost(ghost_type_t type, int access)
{
	ghost_t *ghost ;

	ghost = kmem_cache_alloc(ghost_cachep, GFP_KERNEL);
	if (!ghost)
		goto outofmemory ;

	ghost->type = type ;
	ghost->size = 0 ;
	ghost->ops = NULL ;
	ghost->data = NULL ;
	ghost->access = access ;

	return ghost ;

outofmemory:
	return ERR_PTR(-ENOMEM);
}

/** Free ghost data structures. */
void free_ghost(ghost_t *ghost)
{
	if (ghost->data)
		kfree (ghost->data);

	kmem_cache_free(ghost_cachep, ghost);
}

int ghost_printf(ghost_t *ghost, char *format, ...)
{
	va_list args;
	char *buffer;
	int r, len;

	va_start(args, format);
	buffer = kvasprintf(GFP_KERNEL, format, args);
	va_end(args);

	if (!buffer)
		return -ENOMEM;

	len = strlen(buffer);

	r = ghost_write(ghost, buffer, len);

	kfree(buffer);
	return r;
}

/*****************************************************************************/
/*                                                                           */
/*                              INITIALIZATION                               */
/*                                                                           */
/*****************************************************************************/

int init_ghost(void)
{
	unsigned long cache_flags = SLAB_PANIC;

#ifdef CONFIG_DEBUG_SLAB
	cache_flags |= SLAB_POISON;
#endif
	ghost_cachep = kmem_cache_create("ghost",
					 sizeof(ghost_t),
					 0, cache_flags,
					 NULL);

	return 0;
}

void cleanup_ghost(void)
{
}
