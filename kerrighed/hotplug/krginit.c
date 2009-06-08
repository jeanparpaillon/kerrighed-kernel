/*
 *  Copyright (C) 2006-2007, Pascal Gallard, Kerlabs.
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/workqueue.h>
#include <linux/sysdev.h>

#include <kerrighed/version.h>
#include <kerrighed/types.h>
#include <kerrighed/krginit.h>
#include <kerrighed/krgflags.h>
#include <kerrighed/debug_tools2.h>
#include <linux/cluster_barrier.h>
#include <linux/unique_id.h>
#include <net/krgrpc/rpc.h>
#ifdef CONFIG_KRG_PROC
#include <kerrighed/pid.h>
#endif
#ifdef CONFIG_KRG_HOTPLUG
#include <kerrighed/hotplug.h>
#endif

void init_node_discovering(void);

/* Node id */
kerrighed_node_t kerrighed_node_id = -1;
EXPORT_SYMBOL(kerrighed_node_id);

/* Number of active nodes in the cluster */
kerrighed_node_t kerrighed_nb_nodes = -1;

/* Min number of node before to start a cluster */
kerrighed_node_t kerrighed_nb_nodes_min = -1;

/* Session id in order to mix several krg in the same physical network */
kerrighed_session_t kerrighed_session_id = 0;

/* ID of subcluster in the main one */
kerrighed_subsession_t kerrighed_subsession_id = -1;

/* Initialisation flags */
int kerrighed_init_flags = 0;

/* lock around process transformation and hooks install */
DECLARE_RWSEM(kerrighed_init_sem);
EXPORT_SYMBOL(kerrighed_init_sem);

int kerrighed_cluster_flags;
EXPORT_SYMBOL(kerrighed_cluster_flags);

int kerrighed_node_flags;
EXPORT_SYMBOL(kerrighed_node_flags);

int __krg_panic__ = 0;

struct workqueue_struct *krg_wq;
struct workqueue_struct *krg_nb_wq;

struct kobject* krgsys;
struct kobject* krghotplugsys;

#define deffct(p) extern int init_##p(void); extern void cleanup_##p(void)

deffct(tools);
#ifdef CONFIG_KRG_HOTPLUG
deffct(hotplug);
#endif
#ifdef CONFIG_KRGRPC
deffct(rpc);
#endif
#ifdef CONFIG_KRG_STREAM
deffct(stream);
#endif
deffct(kddm);
deffct(kermm);
#ifdef CONFIG_KRG_DVFS
deffct(dvfs);
#endif
#ifdef CONFIG_KRG_IPC
deffct(keripc);
#endif
#ifdef CONFIG_KRG_CAP
deffct(krg_cap);
#endif
#ifdef CONFIG_KRG_PROCFS
deffct(procfs);
#endif
#ifdef CONFIG_KRG_PROC
deffct(proc);
#endif
#ifdef CONFIG_KRG_EPM
deffct(ghost);
deffct(epm);
#endif
#ifdef CONFIG_KRG_SCHED
deffct(scheduler);
#endif

/*
 * Handle Kernel parameters
 */

static int __init  parse_autonodeid(char *str) {
	int v = 0;
	get_option(&str, &v);
	if(v)
		SET_KRG_INIT_FLAGS(KRG_INITFLAGS_AUTONODEID);
	return 0;
}
__setup("autonodeid=",parse_autonodeid);

static int __init  parse_node_id(char *str) {
	int v;
	get_option(&str, &v);
	kerrighed_node_id = v;
	SET_KRG_INIT_FLAGS(KRG_INITFLAGS_NODEID);
	return 0;
}
__setup("node_id=",parse_node_id);

static int __init  parse_session_id(char *str){
	int v;
	get_option(&str, &v);
	kerrighed_session_id = v;
	SET_KRG_INIT_FLAGS(KRG_INITFLAGS_SESSIONID);
	return 0;
}
__setup("session_id=",parse_session_id);

static int __init  parse_nb_nodes_min(char *str){
	int v;
	get_option(&str, &v);
	kerrighed_nb_nodes_min = v;
	return 0;
}
__setup("nb_nodes_min=",parse_nb_nodes_min);

/*****************************************************************************/
/*                                                                           */
/*                          KERRIGHED INIT FUNCTION                          */
/*                                                                           */
/*****************************************************************************/

static inline void check_node_id (int node_id)
{
	if ((node_id >= KERRIGHED_MAX_NODES) || (node_id < 0))
	{
		printk ("Invalid kerrighed node id %d (Max id = %d)\n",
			node_id, KERRIGHED_MAX_NODES);
		BUG();
	}
}

static char *read_from_file(char *_filename, int size)
{
	int error;
	struct file *f;
	char *b, *filename;

	b = kmalloc(size, GFP_ATOMIC);
	BUG_ON(b==NULL);

	filename = getname(_filename);
	if (!IS_ERR(filename)) {
		f = filp_open(filename, O_RDONLY, 0);
		if (IS_ERR(f)) {
			printk("error: %ld\n", PTR_ERR(f));
			goto err_file;
		}

		error = kernel_read(f, 0, b, size);
		//printk("read %d bytes\n", error);

		b[error] = 0;
		//printk(">>>%s<<<\n", b);

		if (f->f_op && f->f_op->flush) {
			error = f->f_op->flush(f, NULL);
			if (error)
				printk("init_ids: Error while closing file %d\n", error);
		}
	}
	return b;

 err_file:
	kfree(b);
	return NULL;
}

/* Remove then CR (if any) */
static void strip_hostname(char *h)
{
	char *i;

	for (i = h; *i; i++) {
		if (*i == 10) {
			*i=0;
			break;
		}
	}
}

static char *get_next_line(char *k)
{
	char *i;

	BUG_ON(*k==0);

	for (i = k; *i; i++) {
		if (*i == 10)
			return i+1;
	}

	return NULL;
}

static void read_kerrighed_nodes(char *_h, char *k)
{
	char *ik, *h;
	int lh;

	if ((_h==NULL) || (k==NULL))
		return;

	lh = strlen(_h);
	h = kmalloc(lh+1, GFP_ATOMIC);
	strncpy(h, _h, lh);
	h[lh] = ':';
	h[lh+1] = 0;
	lh = strlen(h);

	for (ik=k; ik && *ik;) {
		if (!ISSET_KRG_INIT_FLAGS(KRG_INITFLAGS_SESSIONID)) {
			if (strncmp("session=", ik, 8) == 0){
				ik += 8;
				kerrighed_session_id = simple_strtoul(ik, NULL, 10);
				SET_KRG_INIT_FLAGS(KRG_INITFLAGS_SESSIONID);

				ik = get_next_line(ik);
				continue;
			}
		}

		if (strncmp("nbmin=", ik, 6) == 0) {
			ik += 6;
			kerrighed_nb_nodes_min = simple_strtoul(ik, NULL, 10);
			ik = get_next_line(ik);
			continue;
		}

		if (!ISSET_KRG_INIT_FLAGS(KRG_INITFLAGS_NODEID)) {
			if (strncmp(h, ik, lh) == 0) {
				char *end;
				ik += lh;

				kerrighed_node_id = simple_strtoul(ik, &end, 10);
				SET_KRG_INIT_FLAGS(KRG_INITFLAGS_NODEID);
			}
		}

		ik = get_next_line(ik);
	}
}

static void __init init_ids(void)
{
	char *hostname, *kerrighed_nodes;

	if (!ISSET_KRG_INIT_FLAGS(KRG_INITFLAGS_NODEID) ||
	    !ISSET_KRG_INIT_FLAGS(KRG_INITFLAGS_SESSIONID)) {
		/* first we read the name of the node */
		hostname = read_from_file("/etc/hostname", 256);
		if (!hostname) {
			printk("Can't read /etc/hostname\n");
			goto out;
		}
		strip_hostname(hostname);

		kerrighed_nodes = read_from_file("/etc/kerrighed_nodes", 4096);
		if (!kerrighed_nodes) {
			kfree(hostname);
			printk("Can't read /etc/kerrighed_nodes\n");
			goto out;
		}
		read_kerrighed_nodes(hostname, kerrighed_nodes);

		kfree(kerrighed_nodes);
		kfree(hostname);
	}

 out:
	if (ISSET_KRG_INIT_FLAGS(KRG_INITFLAGS_NODEID)) {
		check_node_id(kerrighed_node_id);
#ifdef CONFIG_KRG_HOTPLUG
		universe[kerrighed_node_id].state = 1;
		set_krgnode_present(kerrighed_node_id);
#endif
	}

	kerrighed_cluster_flags = 0;
	kerrighed_node_flags = 0;
	
	printk("Kerrighed session ID : %d\n", kerrighed_session_id);
	printk("Kerrighed node ID    : %d\n", kerrighed_node_id);
	printk("Kerrighed min nodes  : %d\n", kerrighed_nb_nodes_min);

	if (!ISSET_KRG_INIT_FLAGS(KRG_INITFLAGS_NODEID) ||
	    !ISSET_KRG_INIT_FLAGS(KRG_INITFLAGS_SESSIONID))
		panic("kerrighed: incomplete session ID / node ID settings!\n");

	return;
}

int init_kerrighed_communication_system(void)
{
	printk("Init Kerrighed low-level framework...\n");

	if (init_tools())
		goto err_tools;

	kerrighed_nb_nodes = 0;

#ifdef CONFIG_KRGRPC
	if (init_rpc())
		goto err_rpc;
#endif

#ifdef CONFIG_KRG_HOTPLUG
	if (init_hotplug())
		goto err_hotplug;
#endif

	printk("Init Kerrighed low-level framework (nodeid %d) : done\n", kerrighed_node_id);

	return 0;

#ifdef CONFIG_KRG_HOTPLUG
err_hotplug:
	cleanup_hotplug();
#endif
#ifdef CONFIG_KRGRPC
err_rpc:
#endif
	cleanup_tools();
err_tools:
	return -1;
}

#ifdef CONFIG_KERRIGHED
int init_kerrighed_upper_layers(void)
{
	printk("Init Kerrighed distributed services...\n");

#ifdef CONFIG_KRG_KDDM
	if (init_kddm())
		goto err_kddm;
#endif

#ifdef CONFIG_KRG_EPM
	if (init_ghost())
		goto err_ghost;
#endif

#ifdef CONFIG_KRG_STREAM
	if (init_stream())
		goto err_palantir;
#endif

#ifdef CONFIG_KRG_MM
	if (init_kermm())
		goto err_kermm;
#endif

#ifdef CONFIG_KRG_DVFS
	if (init_dvfs())
		goto err_dvfs;
#endif

#ifdef CONFIG_KRG_IPC
	if (init_keripc())
		goto err_keripc;
#endif

#ifdef CONFIG_KRG_CAP
	if (init_krg_cap())
		goto err_krg_cap;
#endif

#ifdef CONFIG_KRG_PROC
	if (init_proc())
		goto err_proc;
#endif

#ifdef CONFIG_KRG_PROCFS
	if (init_procfs())
		goto err_procfs;
#endif

#ifdef CONFIG_KRG_EPM
	if (init_epm())
		goto err_epm;
#endif

	printk("Init Kerrighed distributed services: done\n");

#ifdef CONFIG_KRG_SCHED
	if (init_scheduler())
		goto err_sched;
#endif

	return 0;

#ifdef CONFIG_KRG_SCHED
	cleanup_scheduler();
      err_sched:
#endif
#ifdef CONFIG_KRG_EPM
	cleanup_epm();
      err_epm:
#endif
#ifdef CONFIG_KRG_IPC
	cleanup_keripc();
      err_keripc:
#endif
#ifdef CONFIG_KRG_DVFS
	cleanup_dvfs();
      err_dvfs:
#endif
#ifdef CONFIG_KRG_PROCFS
	cleanup_procfs();
      err_procfs:
#endif
#ifdef CONFIG_KRG_PROC
	cleanup_proc();
      err_proc:
#endif
#ifdef CONFIG_KRG_CAP
	cleanup_krg_cap();
      err_krg_cap:
#endif
#ifdef CONFIG_KRG_MM
	cleanup_kermm();
      err_kermm:
#endif
#ifdef CONFIG_KRG_KDDM
	cleanup_kddm();
      err_kddm:
#endif
#ifdef CONFIG_KRG_STREAM
	cleanup_stream();
      err_palantir:
#endif
#ifdef CONFIG_KRG_EPM
	cleanup_ghost();
      err_ghost:
#endif
#ifdef CONFIG_KRGRPC
	cleanup_rpc();
#endif
	return -1;
}
#endif

#if 0
static ssize_t kerrighed_operation_show(struct kobject *obj, struct kobj_attribute *attr,
					char *page) {
        return sprintf(page, "blabla\n");
}

static ssize_t kerrighed_operation_store(struct kobject *obj, struct kobj_attribute *attr,
					const char *buf, size_t count) {
	printk("requested_operation: %s\n", buf);
        return count;
}

static struct kobj_attribute operation =
		__ATTR(operation, 0644,
			kerrighed_operation_show,
			kerrighed_operation_store);
#endif

static ssize_t node_id_show(struct kobject *obj, struct kobj_attribute *attr,
			    char *page)
{
	return sprintf(page, "%d\n", kerrighed_node_id);
}
static struct kobj_attribute kobj_attr_node_id =
		__ATTR_RO(node_id);

static ssize_t session_id_show(struct kobject *obj, struct kobj_attribute *attr,
			       char *page)
{
	return sprintf(page, "%d\n", kerrighed_session_id);
}
static struct kobj_attribute kobj_attr_session_id =
		__ATTR_RO(session_id);

static ssize_t subsession_id_show(struct kobject *obj, struct kobj_attribute *attr,
				  char *page)
{
	return sprintf(page, "%d\n", kerrighed_subsession_id);
}
static struct kobj_attribute kobj_attr_subsession_id =
		__ATTR_RO(subsession_id);

static ssize_t max_nodes_show(struct kobject *obj, struct kobj_attribute *attr,
			      char *page)
{
	return sprintf(page, "%d\n", KERRIGHED_MAX_NODES);
}
static struct kobj_attribute kobj_attr_max_nodes =
		__ATTR_RO(max_nodes);

static ssize_t max_subclusters_show(struct kobject *obj, struct kobj_attribute *attr,
				    char *page)
{
	return sprintf(page, "%d\n", KERRIGHED_MAX_CLUSTERS);
}
static struct kobj_attribute kobj_attr_max_subclusters =
		__ATTR_RO(max_subclusters);

static ssize_t abi_show(struct kobject *obj, struct kobj_attribute *attr,
			char *page)
{
	return sprintf(page, "%s\n", KERRIGHED_ABI);
}
static struct kobj_attribute kobj_attr_abi =
		__ATTR_RO(abi);

static struct attribute *attrs[] = {
	&kobj_attr_node_id.attr,
	&kobj_attr_session_id.attr,
	&kobj_attr_subsession_id.attr,
	&kobj_attr_max_nodes.attr,
	&kobj_attr_max_subclusters.attr,
	&kobj_attr_abi.attr,
	NULL
};

static struct attribute_group attr_group = {
	.attrs = attrs,
};

static int init_sysfs(void){
	int r;

	krgsys = kobject_create_and_add("kerrighed", NULL);
	if(!krgsys)
		return -1;

	krghotplugsys = kobject_create_and_add("hotplug", krgsys);
	if(!krghotplugsys)
		return -1;

	r = sysfs_create_group(krgsys, &attr_group);
	if(r)
		kobject_put(krgsys);

	return 0;
}

void __init kerrighed_init(void){
	printk("Kerrighed: stage 0\n");
	init_ids();

	printk("Kerrighed: stage 1\n");

	debug_init("kerrighed");

	init_sysfs();
	krg_wq = create_workqueue("krg");
	krg_nb_wq = create_workqueue("krgNB");
	BUG_ON(krg_wq == NULL);
	BUG_ON(krg_nb_wq == NULL);

	init_unique_ids();
	init_node_discovering();

	printk("Kerrighed: stage 2\n");

	if (init_kerrighed_communication_system())
		return;

	init_cluster_barrier();

#ifdef CONFIG_KERRIGHED
	if (init_kerrighed_upper_layers())
		return;
#endif

	SET_KERRIGHED_CLUSTER_FLAGS(KRGFLAGS_LOADED);
	SET_KERRIGHED_NODE_FLAGS(KRGFLAGS_LOADED);

	printk("Kerrighed... loaded!\n");

	rpc_enable(CLUSTER_START);
	rpc_connect();
}
