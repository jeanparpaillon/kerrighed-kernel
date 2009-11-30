#
# Kerrighed's Enhanced Process Management (EPM) - Application
#

obj-$(CONFIG_KRG_EPM) := krg_epm_application.o

krg_epm_application-y := app_shared.o \
	app_frontier.o application.o \
	app_checkpoint.o app_restart.o \
	application_cr_api.o

EXTRA_CFLAGS += -Wall -Werror
