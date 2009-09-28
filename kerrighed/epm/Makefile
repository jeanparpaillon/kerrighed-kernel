#
# Kerrighed's Enhanced Process Management (EPM)
#

obj-$(CONFIG_KRG_EPM) := krg_epm.o
obj-$(CONFIG_KRG_EPM) += application/

krg_epm-y := epm.o \
	signal.o sighand.o children.o pid.o pidmap.o \
	action.o ghost.o network_ghost.o \
	remote_clone.o migration.o checkpoint.o restart.o \
	hotplug.o \
	procfs.o

EXTRA_CFLAGS += -Wall -Werror
