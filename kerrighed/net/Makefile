#
# Kerrighed's Global Network Services
#

obj-y := net.o
obj-$(CONFIG_KRG_EPM) += checkpoint_skbuff.o checkpoint_tcp.o checkpoint_ip.o checkpoint_sock.o
obj-$(CONFIG_KRG_CLUSTERIP) += krg_clusterip_utils.o krg_clusterip_handlers.o

EXTRA_CFLAGS += -Wall -Werror
