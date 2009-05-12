#
# Makefile for the Kernel Distributed Data Management system
#

obj-$(CONFIG_KRG_KDDM) := kddm.o object.o procfs.o \
	io_linker.o object_server.o protocol_action.o \
	kddm_tree.o \
	name_space.o kddm_set.o \
	kddm_find_object.o kddm_put_object.o kddm_get_object.o \
	kddm_grab_object.o kddm_set_object.o kddm_flush_object.o \
	kddm_remove_object.o kddm_sync_object.o kddm_bench.o kddm_hotplug.o

obj-$(CONFIG_KRG_EPM) += mobility.o

EXTRA_CFLAGS += -Wall -Werror
