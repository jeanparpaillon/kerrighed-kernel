#
# Makefile for the Kerrighed Remote Procedure Call layer
#

obj-y := krginit.o krgsyms.o krg_tools.o krg_syscalls.o procfs.o node_discovering.o 

obj-$(CONFIG_KRG_HOTPLUG) += add.o cluster.o failure.o hooks.o hotplug.o hotplug_notifier.o membership.o namespace.o
obj-$(CONFIG_KRG_HOTPLUG_DEL) += remove.o
obj-$(CONFIG_KRG_HOTPLUG_XCH) += replace.o

EXTRA_CFLAGS += -I$(M) -Wall -Werror

# end of file
