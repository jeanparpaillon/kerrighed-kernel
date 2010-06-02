/** Ghost management interface
 *  @file ghost_api.h
 *
 *  Definition of ghost management interface.
 *  @author Renaud Lottiaux
 */
#ifndef __GHOST_API__
#define __GHOST_API__

#include <asm-generic/errno-base.h>
#include <kerrighed/ghost_types.h>
#include <kerrighed/network_ghost.h>
#include <kerrighed/file_ghost.h>

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/

#define MAX_GHOST_STRING 256

/** Create a new ghost struct.
 *  @author Renaud Lottiaux
 *
 *  @param  type  Type of ghost to create (network, file, etc)
 *
 *  @return        Struct of the created ghost.
 *                 NULL in case of error.
 */
ghost_t *create_ghost(ghost_type_t type, int access);

/** Free ghost data structures.
 *  @author Renaud Lottiaux
 *
 *  @param  ghost  The ghost to free.
 */
void free_ghost(ghost_t *ghost);

/** Generique function to write to a ghost.
 *  @author Renaud Lottiaux
 *
 *  @param  ghost   The ghost to write to.
 *  @param  buff    Address of data to write in the ghost.
 *  @param  length  Length of data to write.
 *
 *  @return        0 if everything ok
 *                 Negative value otherwise.
 */
static inline
int __must_check ghost_write(ghost_t *ghost, const void *buff, size_t length)
{
	int r = 0 ;

	BUG_ON(!ghost);
	BUG_ON(!ghost->ops);
	BUG_ON(!ghost->ops->write);
	BUG_ON(!buff);
	BUG_ON(!(ghost->access & GHOST_WRITE));

	r = ghost->ops->write ( ghost, buff, length );

	return r ;
}

#define ghost_write_type(ghost, v) ghost_write(ghost, &v, sizeof(v))

/** Generic function to write a character string to a ghost.
 *  @author Matthieu Fertré
 *
 *  @param  ghost   The ghost to write to.
 *  @param  str     The characters string to write in the ghost.
 *
 *  @return        0 if everything ok
 *                 Negative value otherwise.
 */
static inline
int __must_check ghost_write_string(ghost_t *ghost, const char* str)
{
	int r;
	size_t len;
	BUG_ON(!str);

	len = strlen(str);
	if (len > MAX_GHOST_STRING)
		return -E2BIG;

	r = ghost_write(ghost, &len, sizeof(len));
	if (r)
		goto err_write;
	r = ghost_write(ghost, str, len+1);
err_write:
	return r;
}

/** Generic function to read from a ghost.
 *  @author Renaud Lottiaux
 *
 *  @param  ghost   The ghost to read from.
 *  @param  buff    Address of buffer to write data in.
 *  @param  length  Length of data to read.
 *
 *  @return        0 if everything ok
 *                 Negative value otherwise.
 */
static inline
int __must_check ghost_read(ghost_t *ghost, void *buff, size_t length)
{
	int r = 0 ;

	BUG_ON (!(ghost->access & GHOST_READ));

	r = ghost->ops->read(ghost, buff, length);

	return r ;
}

#define ghost_read_type(ghost, v) ghost_read(ghost, &v, sizeof(v))

/** Generic function to read a character string from a ghost.
 *
 *  @author Matthieu Fertré
 *
 *  @param  ghost   The ghost to write to.
 *  @param  str     The characters string to read from the ghost.
 *
 *  @return        0 if everything ok
 *                 Negative value otherwise.
 *
 *  User is responsible for having enough place to write the string in the
 *  str buffer
 */
static inline
int __must_check ghost_read_string(ghost_t *ghost, char* str)
{
	int r;
	size_t len;
	BUG_ON(str == NULL);

	r = ghost_read(ghost, &len, sizeof(len));
	if (r)
		goto err_read;

	if (len > MAX_GHOST_STRING)
		return -E2BIG;

	r = ghost_read(ghost, str, len+1);
err_read:
	return r;
}

int __must_check ghost_printf(ghost_t *ghost, char *format, ...);

/** Generic function to close a ghost.
 *  @author Matthieu Fertré
 *
 *  @param  ghost   The ghost to close.
 *
 *  @return        0 if everything ok
 *                 Negative value otherwise.
 */
static inline int ghost_close(ghost_t * ghost)
{
	return ghost->ops->close(ghost);
}

#endif // __GHOST_API__
