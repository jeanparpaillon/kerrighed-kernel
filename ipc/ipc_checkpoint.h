
int sys_msgq_checkpoint(int msqid, int fd);

int sys_msgq_restart(int fd);

int sys_sem_checkpoint(int semid, int fd);

int sys_sem_restart(int fd);

int sys_shm_checkpoint(int semid, int fd);

int sys_shm_restart(int fd);

