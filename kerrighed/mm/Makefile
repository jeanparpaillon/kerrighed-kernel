obj-$(CONFIG_KRG_MM) := krgmm.o

krgmm-y := memory_int_linker.o mm.o vma_struct.o page_table_tree.o \
		   memory_io_linker.o mm_struct.o mm_struct_io_linker.o \
		   mm_server.o injection.o hotplug.o

krgmm-$(CONFIG_KRG_EPM) += mobility.o

EXTRA_CFLAGS += -Wall -Werror
