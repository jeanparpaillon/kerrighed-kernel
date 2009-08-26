#ifndef __KKRG_SHM__
#define __KKRG_SHM__

#include <linux/init.h>
#include <linux/ipc.h>
#include "util.h"

struct vm_area_struct;


/** Kerrighed Hooks **/
int krg_ipc_shm_newseg(struct ipc_namespace *ns, struct shmid_kernel * shp);
void krg_ipc_shm_destroy(struct ipc_namespace *ns, struct shmid_kernel *shp);
void krg_ipc_shm_rmkey(struct ipc_namespace *ns, key_t key);

/** Exported variables  **/

extern struct vm_operations_struct shm_vm_ops;
extern struct vm_operations_struct krg_shmem_vm_ops;

extern const struct file_operations shm_file_operations;

/** Exported functions  **/

int newseg(struct ipc_namespace *ns, struct ipc_params *params);

struct shm_file_data {
	int id;
	struct ipc_namespace *ns;
	struct file *file;
	const struct vm_operations_struct *vm_ops;
};

#define shm_file_data(file) (*((struct shm_file_data **)&(file)->private_data))

static inline struct shmid_kernel* local_shm_lock(struct ipc_namespace *ns,
						  int id)
{
	struct kern_ipc_perm *ipcp = local_ipc_lock(&shm_ids(ns), id);

	if (IS_ERR(ipcp))
		return (struct shmid_kernel *)ipcp;

	return container_of(ipcp, struct shmid_kernel, shm_perm);
}

struct shmid_kernel *shm_lock(struct ipc_namespace *ns, int id);
struct shmid_kernel *shm_lock_check(struct ipc_namespace *ns, int id);

static inline void local_shm_unlock(struct shmid_kernel *shp)
{
	local_ipc_unlock(&(shp)->shm_perm);
}

static inline void shm_unlock(struct shmid_kernel *shp)
{
	ipc_unlock(&(shp)->shm_perm);
}

void local_shm_destroy(struct ipc_namespace *ns, struct shmid_kernel *shp);

#endif // __KKRG_SHM__
