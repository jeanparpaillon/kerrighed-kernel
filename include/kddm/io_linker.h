/** KDDM IO linker interface.
 *  @file io_linker.h
 *
 *  Create link between KDDM and io linkers.
 *  @author Renaud Lottiaux
 */

#ifndef __IO_LINKER__
#define __IO_LINKER__

#include <kerrighed/krgnodemask.h>
#include <kerrighed/krginit.h>
#include <kerrighed/sys/types.h>

#include <kddm/kddm_types.h>
#include <kddm/object.h>



/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                 MACROS                                   *
 *                                                                          *
 *--------------------------------------------------------------------------*/



/** IO linker types  */

enum
  {
    MEMORY_LINKER,
    FILE_LINKER,
    DIR_LINKER,
    SHM_MEMORY_LINKER,
    INODE_LINKER,
    FILE_STRUCT_LINKER,
    TASK_LINKER,
    SIGNAL_STRUCT_LINKER,
    SIGHAND_STRUCT_LINKER,
    STATIC_NODE_INFO_LINKER,
    STATIC_CPU_INFO_LINKER,
    DYNAMIC_NODE_INFO_LINKER,
    DYNAMIC_CPU_INFO_LINKER,
    STREAM_LINKER,
    SOCKET_LINKER,
    APP_LINKER,
    FUTEX_LINKER,
    IPCMAP_LINKER,
    SHMID_LINKER,
    SHMKEY_LINKER,
    SEMARRAY_LINKER,
    SEMUNDO_LINKER,
    SEMKEY_LINKER,
    MSG_LINKER,
    MSGKEY_LINKER,
    MSGMASTER_LINKER,
    DSTREAM_LINKER,
    DSOCKET_LINKER,
    PID_LINKER,
    CHILDREN_LINKER,
    DVFS_FILE_STRUCT_LINKER,
    GLOBAL_LOCK_LINKER,
    STRING_LIST_LINKER,
    KDDM_TEST_LINKER,
    MM_STRUCT_LINKER,
    PIDMAP_MAP_LINKER,
    UNIQUE_ID_LINKER,
    MAX_IO_LINKER, /* MUST always be the last one */
  } ;



#define KDDM_IO_KEEP_OBJECT 1



/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                  TYPES                                   *
 *                                                                          *
 *--------------------------------------------------------------------------*/



struct rpc_desc;

/** IO linker struct
 *  Describe IO linker interface functions, name, etc.
 */

struct iolinker_struct {
  int (*instantiate) (struct kddm_set * set, void *private_data, int master);
  void (*uninstantiate) (struct kddm_set * set, int destroy);
  int (*first_touch) (struct kddm_obj * obj_entry, struct kddm_set * set,
		      objid_t objid, int flags);
  int (*remove_object) (void *object, struct kddm_set * set,
                        objid_t objid);
  int (*invalidate_object) (struct kddm_obj * obj_entry, struct kddm_set * set,
                            objid_t objid);
  int (*flush_object) (struct kddm_obj * obj_entry, struct kddm_set * set,
		       objid_t objid);
  int (*insert_object) (struct kddm_obj * obj_entry, struct kddm_set * set,
                        objid_t objid);
  int (*put_object) (struct kddm_obj * obj_entry, struct kddm_set * set,
		     objid_t objid);
  int (*sync_object) (struct kddm_obj * obj_entry, struct kddm_set * set,
                      objid_t objid);
  void (*change_state) (struct kddm_obj * obj_entry, struct kddm_set * set,
                         objid_t objid, kddm_obj_state_t state);
  int (*alloc_object) (struct kddm_obj * obj_entry, struct kddm_set * set,
                       objid_t objid);
  int (*import_object) (struct rpc_desc *desc, struct kddm_set *set,
			struct kddm_obj *obj_entry, objid_t objid, int flags);
  int (*export_object) (struct rpc_desc *desc, struct kddm_set *set,
			struct kddm_obj *obj_entry, objid_t objid, int flags);
  kerrighed_node_t (*default_owner) (struct kddm_set * set, objid_t objid,
                                     const krgnodemask_t * nodes, int nr_nodes);
  char linker_name[16];
  iolinker_id_t linker_id;
};



/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/



/** Initialize IO linkers.
 *  @author Renaud Lottiaux
 */
void io_linker_init (void);
void io_linker_finalize (void);



/** Register a new kddm IO linker.
 *  @author Renaud Lottiaux
 *
 *  @param io_linker_id
 *  @param linker
 */
int register_io_linker (int linker_id, struct iolinker_struct *io_linker);



/** Instantiate a kddm set.
 *  @author Renaud Lottiaux
 *
 *  @param set           KDDM set to instantiate
 *  @param link          Node linked to the kddm set
 *  @param iolinker_id   Id of the iolinker to link to the kddm set
 *  @param private_data  Data used by the instantiator...
 *
 *  @return error code or 0 if everything ok.
 */
int kddm_io_instantiate (struct kddm_set * set, kerrighed_node_t link,
			 iolinker_id_t iolinker_id, void *private_data,
			 int data_size, int master);



/** Uninstantiate a KDDM set.
 *  @author Renaud Lottiaux
 *
 *  @param set          Kddm set to uninstantiate
 */
void kddm_io_uninstantiate (struct kddm_set * set, int destroy);



/** Do an object first touch.
 *  @author Renaud Lottiaux
 *
 *  @param set          Kddm Set the object belong to.
 *  @param objid        Id of the object to first touch.
 *  @param obj_entry    Object entry the object belong to.
 *  @param objectState  Initial state of the object.
 */
int kddm_io_first_touch_object (struct kddm_obj * obj_entry,
				struct kddm_set * set, objid_t objid,
				int flags);



/** Put a KDDM object.
 *  @author Renaud Lottiaux
 *
 *  @param set          Kddm Set the object belong to.
 *  @param objid        Id of the object to put.
 *  @param obj_entry    Object entry the object belong to.
 */
int kddm_io_put_object (struct kddm_obj * obj_entry, struct kddm_set * set,
                        objid_t objid);



/** Insert an object in a kddm set.
 *  @author Renaud Lottiaux
 *
 *  @param set          Kddm Set the object belong to.
 *  @param objid        Id of the object to insert.
 *  @param obj_entry    Object entry the object belong to.
 */
int kddm_io_insert_object (struct kddm_obj * obj_entry, struct kddm_set * set,
                           objid_t objid);



/** Request an IO linker to invalidate an object.
 *  @author Renaud Lottiaux
 *
 *  @param set          Kddm Set the object belong to.
 *  @param objid        Id of the object to invalidate.
 *  @param obj_entry    Object entry the object belong to.
 */
int kddm_io_invalidate_object (struct kddm_obj * obj_entry, struct kddm_set * set,
                               objid_t objid);



/** Request an IO linker to remove an object.
 *  @author Renaud Lottiaux
 *
 *  @param set          Kddm Set the object belong to.
 *  @param objid        Id of the object to remove.
 *  @param obj_entry    Object entry the object belong to.
 */
int kddm_io_remove_object_and_unlock (struct kddm_obj * obj_entry, struct kddm_set * set,
				      objid_t objid, struct kddm_obj_list **dead_list);

int kddm_io_remove_object (void *object, struct kddm_set * set, objid_t objid);



/** Request an IO linker to sync an object.
 *  @author Renaud Lottiaux
 *
 *  @param set          Kddm Set the object belong to.
 *  @param objid        Id of the object to sync.
 *  @param obj_entry    Object entry the object belong to.
 */
int kddm_io_sync_object (struct kddm_obj * obj_entry, struct kddm_set * set,
                         objid_t objid);



/** Inform an IO linker that an object state has changed.
 *  @author Renaud Lottiaux
 *
 *  @param obj_entry    Object entry the object belong to.
 *  @param set          Kddm Set the object belong to.
 *  @param objid        Id of the object to sync.
 *  @param new_state    New state for the object.
 */
int kddm_io_change_state (struct kddm_obj * obj_entry,
			  struct kddm_set * set,
			  objid_t objid,
			  kddm_obj_state_t new_state);



/** Request an IO linker to import data into an object.
 *  @author Renaud Lottiaux
 *
 *  @param set          Kddm Set the object belong to.
 *  @param obj_entry    Object entry to import data into.
 *  @param buffer       Buffer containing data to import.
 */
int kddm_io_import_object (struct rpc_desc *desc, struct kddm_set *set,
			   struct kddm_obj *obj_entry, objid_t objid,
			   int flags);

/** Request an IO linker to export data from an object.
 *  @author Renaud Lottiaux
 *
 *  @param set          Kddm Set the object belong to.
 *  @param obj_entry    Object entry to export data from.
 *  @param buffer       Buffer to export data to.
 */
int kddm_io_export_object (struct rpc_desc *desc, struct kddm_set *set,
			   struct kddm_obj *obj_entry, objid_t objid,
			   int flags);
kerrighed_node_t kddm_io_default_owner (struct kddm_set * set, objid_t objid);

/** Request an IO linker to allocate an object.
 *  @author Renaud Lottiaux
 *
 *  @param obj_entry   Object entry to export data from.
 *  @param set         Kddm Set the object belong to.
 */
int kddm_io_alloc_object (struct kddm_obj * obj_entry, struct kddm_set * set,
			  objid_t objid);

#endif // __IO_LINKER__
