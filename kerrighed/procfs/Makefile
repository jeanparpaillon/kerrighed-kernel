#
# Makefile for Kerrighed's global ProcFs
#

obj-$(CONFIG_KRG_PROCFS) := krg_procfs.o

krg_procfs-y := procfs.o proc.o \
        static_node_info_linker.o static_cpu_info_linker.o \
        dynamic_node_info_linker.o dynamic_cpu_info_linker.o \
	procfs_hotplug.o

krg_procfs-$(CONFIG_KRG_PROC) += proc_pid.o \
	proc_pid_file.o proc_pid_link.o \
	proc_pid_fd.o

EXTRA_CFLAGS += -Wall -Werror
