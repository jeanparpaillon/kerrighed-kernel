#
# Kerrighed's configurable scheduler framework (SCHED)
#

obj-$(CONFIG_KRG_SCHED) := core.o info.o \
	string_list.o hashed_string_list.o global_config.o \
	policy.o scheduler.o \
	pipe.o remote_pipe.o \
	probe.o port.o filter.o \
	process_set.o placement.o

obj-$(CONFIG_KRG_SCHED) += probes/
obj-$(CONFIG_KRG_SCHED) += filters/
obj-$(CONFIG_KRG_SCHED) += policies/

EXTRA_CFLAGS += -Wall -Werror
