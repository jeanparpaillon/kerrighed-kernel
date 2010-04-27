#include <linux/fs.h>
#include <kerrighed/fcntl.h>

/** Kerrighed Kernel Hooks **/
loff_t krg_file_pos_read(struct file *file);
void krg_file_pos_write(struct file *file, loff_t pos);
void krg_put_file(struct file *file);

static inline loff_t file_pos_read(struct file *file)
{
	if (file->f_flags & O_KRG_SHARED)
		file->f_pos = krg_file_pos_read(file);
	return file->f_pos;
}

static inline void file_pos_write(struct file *file, loff_t pos)
{
	if (file->f_flags & O_KRG_SHARED)
		krg_file_pos_write(file, pos);
	file->f_pos = pos;
}
