/*
 * Get information about file
 *
 * Copyright (C) 2009, Matthieu Fertré, Kerlabs.
 */

#ifndef __KRG_FILE_STAT__
#define __KRG_FILE_STAT__

struct file;

int is_pipe(const struct file *file);

int is_anonymous_pipe(const struct file *file);

int is_named_pipe(const struct file *file);

int is_socket(const struct file *file);

int is_shm(const struct file *file);

int is_char_device(const struct file *file);

int is_block_device(const struct file *file);

int is_directory(const struct file *file);

int is_link(const struct file *file);

int is_tty(const struct file *file);

int is_anon_shared_mmap(const struct file *file);

int is_posix_mqueue(const struct file *file);

int is_eventpoll(const struct file *file);

int is_signal(const struct file *file);

int is_timer(const struct file *file);

/*
 * Return the 'physical' name of a file.
 * The filesystem must be mounted else it return NULL
 * Returns NULL if file is deleted and del_ok is false
 *
 * buffer must have a size of PAGE_SIZE
 */
char *get_phys_filename(struct file *file, char *buffer, bool del_ok);

/*
 * Return the name of a file as visible in /proc/<pid>/fd.
 * Virtual files such as socket, and anonymous pipe get a name.
 *
 * buffer must have a size of PAGE_SIZE
 */
char *get_filename(struct file *file, char *buffer);

char *alloc_filename(struct file *file, char **buffer);

void free_filename(char *buffer);

int can_checkpoint_file(const struct file *file);

int can_export_file(const struct file *file);

#endif
