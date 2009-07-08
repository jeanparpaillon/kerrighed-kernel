/** DVFS debug system.
 *  @file debug_dvfs.c
 *
 *  Copyright (C) 2007, Renaud Lottiaux, Kerlabs.
 */
#include <linux/sched.h>
#include <linux/kallsyms.h>
#include <kerrighed/dvfs.h>

#include <kerrighed/pid.h>
#include <kerrighed/debug_color.h>
#include <kerrighed/file.h>
#include <kerrighed/physical_fs.h>
#include "debug_fs.h"

pid_t debug_dvfs_last_pid = 0;
struct dentry *dvfs_debug_dentry;
struct dentry *dvfs_filter_dentry;

int print_fd (char *buffer, int fd)
{
	int n = 0;
	if (fd == 4095)
		n = sprintf (buffer, "[-] ");
	else
		n = sprintf (buffer, "[%d] ", fd);

	return n;
}

int print_flags (char *buffer, unsigned long flags)
{
	int n = 0;

	if (flags & O_RDONLY)
		n += sprintf (&buffer[n], "RDONLY ");

	if (flags & O_WRONLY)
		n += sprintf (&buffer[n], "WRONLY ");

	if (flags & O_RDWR)
		n += sprintf (&buffer[n], "RDWR ");

	if (flags & O_FAF_CLT)
		n += sprintf (&buffer[n], "FAF_CLT ");

	if (flags & O_FAF_SRV)
		n += sprintf (&buffer[n], "FAF_SRV ");

	if (flags & O_KRG_SHARED)
		n += sprintf (&buffer[n], "DVFS_SHARED ");

	n += sprintf (&buffer[n], "\n");

	return n;
}

void dvfs_print_log(struct dvfs_log *log, char *buffer)
{
	char *modname;
	const char *name;
	unsigned long offset, size;
	char namebuf[KSYM_NAME_LEN+1];
	int n = 0, fd, srv_fd, srv_id;

	srv_id = DVFS_LOG_UNPACKFD1 (log);
	fd = DVFS_LOG_UNPACKFD2 (log);
	srv_fd = DVFS_LOG_UNPACKFD3 (log);

	name = kallsyms_lookup(log->fct_addr, &size, &offset, &modname,
			       namebuf);

	n += sprintf (&buffer[n], "%6d - %30.30s ", log->current_pid, name);
	n += print_fd (&buffer[n], fd);

	if (srv_id == 255)
		n += sprintf (&buffer[n], "(-;- / ");
	else
		n += sprintf (&buffer[n], "(%d;%d / ", srv_id, srv_fd);

	if (log->objid == -1UL)
		n += sprintf (&buffer[n], "-) ");
	else
		n += sprintf (&buffer[n], "%ld) ", log->objid);

	switch (log->dbg_id) {
	case DVFS_LOG_ENTER:
	case FAF_LOG_ENTER:
		n += sprintf (&buffer[n], "Enter\n");
		break;

	case DVFS_LOG_ENTER_PUT_DVFS:
		n += sprintf (&buffer[n], "New DVFS count %d - file %p count "
			      "%d\n", (int)log->data, log->file,
			      (int)log->data2);
		break;

	case FAF_LOG_ACCEPT_DONE:
		n += sprintf (&buffer[n], "Accept has created file %p - "
			      "DVFS count %d - file count %d\n", log->file,
			      (int)log->data, (int)log->data2);
		break;

	case DVFS_LOG_ENTER_EXPORT_VMA:
		n += sprintf (&buffer[n], "Export VMA [0x%08lx:0x%08lx] (file "
			      "%p) for process %d\n", log->data, log->data2,
			      log->file, log->task_pid);
		break;

	case DVFS_LOG_ENTER_IMPORT_VMA:
		n += sprintf (&buffer[n], "Import VMA [0x%08lx:0x%08lx] for "
			      "process %d\n", log->data, log->data2,
			      log->task_pid);
		break;

	case DVFS_LOG_ENTER_EXPORT_FILE:
		n += sprintf (&buffer[n], "-- EXPORT FILE ");
		n += print_fd (&buffer[n], fd);
		n += sprintf(&buffer[n], "= %p (count %d) for process %d --"
			     " Flags: ", log->file, (int)log->data,
			     log->task_pid);
		n += print_flags (&buffer[n], log->data2);
		break;

	case DVFS_LOG_ENTER_IMPORT_FILE:
		n += sprintf (&buffer[n], "-- IMPORT FILE ");
		n += print_fd (&buffer[n], fd);
		n += sprintf (&buffer[n], "for process %d --\n",log->task_pid);
		break;

	case DVFS_LOG_EXIT:
	case FAF_LOG_EXIT:
		n += sprintf (&buffer[n], "Done (err %d)\n", (int)log->data);
		break;

	case DVFS_LOG_EXIT_GET_DVFS:
		n += sprintf (&buffer[n], "New DVFS count %d - file %p count "
			      "%d\n", (int)log->data, log->file,
			      (int)log->data2);
		break;

	case DVFS_LOG_EXIT_EXPORT_FILE:
		n += sprintf (&buffer[n], "-- EXPORT FILE DONE ");
		n += print_fd (&buffer[n], fd);
		n += sprintf(&buffer[n], "= %p (count %d) for process %d "
			     "-- Flags: ",log->file, (int)log->data,
			     log->task_pid);
		n += print_flags (&buffer[n], log->data2);
		break;

	case DVFS_LOG_EXIT_IMPORT_FILE:
		n += sprintf (&buffer[n], "-- IMPORT FILE DONE ");
		n += print_fd (&buffer[n], fd);
		n += sprintf (&buffer[n], "= %p (count %d) for process %d "
			      "-- Flags: ", log->file,
			      (int)log->data, log->task_pid);
		n += print_flags (&buffer[n], log->data2);
		break;

	case DVFS_LOG_EXIT_CREATE_OBJID:
		n += sprintf (&buffer[n], "Create file object %ld\n",
			      log->data);
		break;

	case DVFS_LOG_IMPORT_INFO:
		n += sprintf (&buffer[n], "Found file %p in container. File "
			      "%p opened by the import function\n",
			      log->file, (void *)log->data);
		break;

	case DVFS_LOG_EXPORT_REG_FILE:
		n += sprintf (&buffer[n], "Export regular file %s\n",
			      log->filename);
		break;

	case FAF_LOG_SETUP_FILE:
		n += sprintf (&buffer[n], "File %p added to the FAF server "
			      "at index %d (count %d)\n", log->file, srv_fd,
			      (int)log->data);
		break;

	case FAF_LOG_CLOSE_SRV_FILE:
		n += sprintf (&buffer[n], "Close FAF server file %p\n",
			      log->file);
		break;

	case FAF_LOG_EXPORT_FAF_FILE:
		n += sprintf (&buffer[n], "Export FAF file\n");
		break;

	default:
		BUG();
		break;
	}
}



void dvfs_save_log(unsigned long eip,
		   const char* module,
		   const char* mask,
		   int level,
		   int fd,
		   int server_id,
		   int server_fd,
		   unsigned long objid,
		   struct task_struct *tsk,
		   struct file *file,
		   int dbg_id,
		   unsigned long data)
{
	char *tmp = NULL, *file_name = NULL;
	struct dvfs_file_struct *dvfs_file;
	struct vm_area_struct *vma;
	struct dvfs_log *log;
	char buffer[256];
	int len = 0;

	if (!match_debug(module, mask, level))
		return;

	if (dbg_id == DVFS_LOG_EXPORT_REG_FILE) {
		tmp = (char *) __get_free_page (GFP_KERNEL);
		file_name = physical_d_path(&file->f_path, tmp);

		if (file_name)
			len = strlen (file_name);
	}

	log = kmalloc (len + sizeof(*log), GFP_ATOMIC);
	if (log == NULL) {
		printk ("Out of memory...\n");
		BUG();
	}

	log->next = NULL;
	log->current_pid = task_pid_knr(current);
	if (tsk)
		log->task_pid = task_pid_knr(tsk);
	else
		log->task_pid = 0;
	log->fct_addr = eip;
	log->dbg_id = dbg_id;
	log->objid = objid;
	log->file = file;
	log->fd = DVFS_LOG_PACKFD (server_id, fd, server_fd);

	switch (dbg_id) {
	  case DVFS_LOG_ENTER_EXPORT_VMA:
	  case DVFS_LOG_ENTER_IMPORT_VMA:
		  vma = (struct vm_area_struct *) data;
		  log->data = vma->vm_start;
		  log->data2 = vma->vm_end;
		  break;

	  case DVFS_LOG_ENTER_EXPORT_FILE:
	  case DVFS_LOG_EXIT_EXPORT_FILE:
	  case DVFS_LOG_EXIT_IMPORT_FILE:
	  case FAF_LOG_SETUP_FILE:
		  if (file) {
			  log->data = atomic_read(&file->f_count);
			  log->data2 = file->f_flags;
		  } else {
			  log->data = 0;
			  log->data2 = 0;
		  }
		  break;

	  case DVFS_LOG_ENTER_PUT_DVFS:
	  case DVFS_LOG_EXIT_GET_DVFS:
		  dvfs_file = (struct dvfs_file_struct *) data;
		  log->data = dvfs_file->count;
		  if (file)
			  log->data2 = atomic_read(&file->f_count);
		  else
			  log->data2 = 0;
		  break;

	  case FAF_LOG_ENTER:
	  case FAF_LOG_EXIT:
	  case DVFS_LOG_ENTER:
	  case DVFS_LOG_EXIT:
	  case FAF_LOG_CLOSE_SRV_FILE:
		  log->data = data;
		  if (file)
			  log->data2 = atomic_read(&file->f_count);
		  else
			  log->data2 = -42;
		  break;

	  case DVFS_LOG_EXPORT_REG_FILE:
		  strncpy (log->filename, file_name, len + 1);
		  free_page ((unsigned long) tmp);
		  break;

	  default:
		  log->data = data;
		  break;
	}

	dvfs_print_log(log, buffer);
	printk ("%s", buffer);
	kfree (log);
}

void init_dvfs_debug(void)
{
	dvfs_debug_dentry = debug_define("dvfs", 0);
	DEBUG_MASK("dvfs", "mobility");
	DEBUG_MASK("dvfs", "reg_file_mgr");
	DEBUG_MASK("dvfs", "file");
	DEBUG_MASK("dvfs", "file_io_linker");
}
