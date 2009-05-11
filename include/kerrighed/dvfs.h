/** Kerrighed Kernel Hooks **/

loff_t krg_file_pos_read(struct file *file);
void krg_file_pos_write(struct file *file, loff_t pos);
void krg_put_file(struct file *file);
