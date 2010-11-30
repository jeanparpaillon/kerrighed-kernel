#
# Kerrighed's Global Network Services
#

obj-y := net.o
obj-$(CONFIG_KRG_EPM) += checkpoint_skbuff.o checkpoint_ip.o checkpoint_sock.o
obj-$(CONFIG_KRG_CLUSTERIP) += krg_clusterip.o

EXTRA_CFLAGS += -Wall -Werror
