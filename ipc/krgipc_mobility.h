#include <kerrighed/ghost.h>

struct msg_queue;
struct ipc_namespace;

int __sys_msgq_checkpoint(int msqid, int fd);

void handle_msg_checkpoint(struct rpc_desc *desc, void *_msg, size_t size);

int import_full_sysv_msgq(ghost_t *ghost);

int export_full_sysv_sem(ghost_t *ghost, int semid);

int import_full_sysv_sem(ghost_t *ghost);

int export_full_sysv_shm(ghost_t *ghost, int shmid);

int import_full_sysv_shm(ghost_t *ghost);

int export_full_all_msgs(ghost_t * ghost, struct msg_queue *msq);

int import_full_all_msgs(ghost_t *ghost, struct ipc_namespace *ns,
			 struct msg_queue *msq);

