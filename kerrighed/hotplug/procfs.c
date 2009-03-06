/** Definition of /proc/kerrighed.
 *  @file procfs.c
 *
 *  Copyright (C) 2006-2008, Renaud Lottiaux, Kerlabs.
 */
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/types.h>
#include <kerrighed/procfs.h>

#define KRG_VERSION "$Name:  $ ($Date: 2004/11/29 17:44:08 $):1.0-rc4"

struct proc_dir_entry *proc_kerrighed = NULL;
EXPORT_SYMBOL(proc_kerrighed);

/** Generic read function for 'unsigned long long' entry.
 *  @author Pascal Gallard
 *
 *  @param buffer           Buffer to write data to.
 *  @param buffer_location  Alternative buffer to return...
 *  @param offset           Offset of the first byte to write in the buffer.
 *  @param buffer_length    Length of given buffer
 *
 *  @return  Number of bytes written.
 */

#define CREATE_PROCFS_READ_TYPE(label, type, format) \
  int procfs_read_##label(char *buffer, char **start, \
                          off_t offset, int count, int *eof, \
                          void *data) { \
    count = sprintf(buffer, format"\n", *(type*)data); \
    *eof = 1; \
    return count; \
}

CREATE_PROCFS_READ_TYPE(int, int, "%d");
CREATE_PROCFS_READ_TYPE(unsigned_int, unsigned int, "%u");

CREATE_PROCFS_READ_TYPE(long, long, "%ld");
CREATE_PROCFS_READ_TYPE(unsigned_long, unsigned long, "%lu");

CREATE_PROCFS_READ_TYPE(long_long, long long, "%lld");
CREATE_PROCFS_READ_TYPE(unsigned_long_long, unsigned long long, "%llu");

/** Close a dir tree in the /proc/kerrighed
 *  @author Gael Utard.
 */
void procfs_deltree(struct proc_dir_entry *entry)
{
	struct proc_dir_entry *subdir, *next;

	subdir = entry->subdir;
	if (subdir) {
		for (next = subdir->next; next;
		     subdir = next, next = subdir->next)
			procfs_deltree(subdir);

		procfs_deltree(subdir);
	}

	remove_proc_entry(entry->name, entry->parent);
}
EXPORT_SYMBOL(procfs_deltree);

static char *krg_version = "Kerrighed v1.0-RC1 (" KRG_VERSION
#ifdef CONFIG_SMP
    " SMP"
#endif
#ifdef CONFIG_DEBUG_KERNEL
    " DEBUG"
#  ifdef CONFIG_DEBUG_STACKOVERFLOW
    " +stackoverflow"
#  endif
#  ifdef CONFIG_DEBUG_HIGHMEM
    " +highmem"
#  endif
#  ifdef CONFIG_DEBUG_SLAB
    " +slab"
#  endif
#  ifdef CONFIG_DEBUG_IOVIRT
    " +iovirt"
#  endif
#  ifdef CONFIG_MAGIC_SYSRQ
    " +sysrq"
#  endif
#  ifdef CONFIG_DEBUG_SPINLOCK
    " +spinlock"
#  endif
#  ifdef CONFIG_FRAME_POINTER
    " +frame_pointer"
#  endif
#  ifdef CONFIG_KDB
    " +kdb"
#  endif
#  ifdef CONFIG_KALLSYMS
    " +kallsyms"
#  endif
#endif
    ;

int read_version(char *buffer, char **start, off_t offset,
		 int count, int *eof, void *data)
{
	static char mybuffer[256];
	static int len;

	if (offset == 0)
		len = snprintf(mybuffer, 256, "%s\n", krg_version);

	if (offset + count >= len) {
		count = len - offset;
		if (count < 0)
			count = 0;
		*eof = 1;
	}

	memcpy(buffer, &mybuffer[offset], count);

	return count;
}

/** Initialisation of the /proc/kerrighed directory.
 *  @author Renaud Lottiaux
 */
int kerrighed_proc_init()
{
	int err = 0;

	/* Create the /proc/kerrighed */

	proc_kerrighed = create_proc_entry("kerrighed", S_IFDIR | 0755, NULL);

	if (proc_kerrighed == NULL)
		err = -EMFILE;

	return err;
}

/** Destroy of the /proc/kerrighed directory.
 *  @author Renaud Lottiaux
 */
void kerrighed_proc_finalize()
{
	remove_proc_entry("kerrighed", NULL);
}
