#include <kerrighed/ghost.h>

int export_full_sysv_msgq(ghost_t *ghost, int msgid);

int import_full_sysv_msgq(ghost_t *ghost);

int export_full_sysv_sem(ghost_t *ghost, int semid);

int import_full_sysv_sem(ghost_t *ghost);
