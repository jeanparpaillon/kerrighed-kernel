#
# Kerrighed's low-level Process monitoring and control
#

obj-$(CONFIG_KRG_PROC) := krg_proc.o

krg_proc-y := proc.o libproc.o \
	task.o krg_exit.o \
	remote_cred.o remote_syscall.o

EXTRA_CFLAGS += -Wall -Werror
