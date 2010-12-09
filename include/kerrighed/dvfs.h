#include <linux/fs.h>
#include <kerrighed/fcntl.h>

/** Kerrighed Kernel Hooks **/
loff_t krg_file_pos_read(struct file *file);
void krg_file_pos_write(struct file *file, loff_t pos);
void krg_put_file(struct file *file);

static inline loff_t file_pos_read(struct file *file)
{
	if (file->f_flags & O_KRG_SHARED) {
		file->f_pos = krg_file_pos_read(file);
		printk ("%d - read pos %ld (objid %ld)\n", current->pid,
			(long int)file->f_pos, (long int)file->f_objid);
	}
	return file->f_pos;
}

static inline void file_pos_write(struct file *file, loff_t pos)
{
	if (file->f_flags & O_KRG_SHARED) {
		krg_file_pos_write(file, pos);
		printk ("%d - write pos %ld (objid %ld)\n", current->pid,
			(long int)pos, (long int)file->f_objid);
	}
	file->f_pos = pos;
}
