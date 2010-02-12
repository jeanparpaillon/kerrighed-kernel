#
# Makefile for the linux ipc.
#

obj-$(CONFIG_SYSVIPC_COMPAT) += compat.o
obj-$(CONFIG_SYSVIPC) += util.o msgutil.o msg.o sem.o shm.o ipcns_notifier.o
obj-$(CONFIG_SYSVIPC_SYSCTL) += ipc_sysctl.o
obj_mq-$(CONFIG_COMPAT) += compat_mq.o
obj-$(CONFIG_POSIX_MQUEUE) += mqueue.o msgutil.o $(obj_mq-y)
obj-$(CONFIG_IPC_NS) += namespace.o
obj-$(CONFIG_POSIX_MQUEUE_SYSCTL) += mq_sysctl.o
obj-$(CONFIG_KRG_IPC) += ipcmap_io_linker.o ipc_handler.o msg_io_linker.o msg_handler.o semarray_io_linker.o semundolst_io_linker.o sem_handler.o shmid_io_linker.o shm_memory_linker.o shm_handler.o hotplug.o
obj-$(CONFIG_KRG_IPC_EPM) += krgipc_mobility.o ipc_checkpoint.o
