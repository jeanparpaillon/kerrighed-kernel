obj-$(CONFIG_KRG_DVFS) := krg_fs.o
obj-$(CONFIG_KRG_FAF) += faf/

krg_fs-y := file_struct_io_linker.o physical_fs.o file.o fs.o file_stat.o hotplug.o
krg_fs-$(CONFIG_KRG_EPM) += regular_file_mgr.o mobility.o

krg_fs-$(CONFIG_KRG_STREAM) +=
#krg_fs-$(CONFIG_KRG_DEBUG) += debug_fs.o

EXTRA_CFLAGS += -Wall -Werror
