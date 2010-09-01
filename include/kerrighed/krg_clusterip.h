#ifndef __KRG_CLUSTERIP_H__
#define __KRG_CLUSTERIP_H__

#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/types.h>

struct kddm_set;

struct krgip_local_port {
	struct list_head list;
	__be16 port;
	struct rcu_head rcu;
};

struct krgip_local_ports {
	spinlock_t lock;
	struct list_head udp;
	struct list_head tcp;
	struct list_head list;
	__be32 addr;
	struct rcu_head rcu;
};

struct krgip_cluster_ip_kddm_object {
	struct krgip_local_ports *local_ports;
	int nr_nodes;
	__be32 addr;
};

struct krgip_addr {
	struct list_head list;
	__be32 addr;
};

struct krgip_cluster_port_kddm_object {
	struct list_head ips;
	kerrighed_node_t node;
	__be16 num;
};

struct netns_krgip {
	struct kddm_set *cluster_ips;
	struct kddm_set *cluster_ports_udp;
	struct kddm_set *cluster_ports_tcp;
	struct list_head *local_ports_ip_table;
	struct krgip_local_ports local_ports_any;
};

struct krgip_local_port *krgip_local_port_alloc(__be16 num);
void krgip_local_port_free(struct krgip_local_port *port);

void krgip_local_ports_add(struct krgip_local_ports *ports,
			   struct krgip_local_port *port,
			   struct list_head *head);
void krgip_local_ports_del(struct krgip_local_ports *ports,
			   __be16 snum,
			   struct list_head *head);

static inline void krgip_local_ports_udp_add(struct krgip_local_ports *ports,
					     struct krgip_local_port *port)
{
	krgip_local_ports_add(ports, port, &ports->udp);
}

static inline void krgip_local_ports_udp_del(struct krgip_local_ports *ports,
					     __be16 snum)
{
	krgip_local_ports_del(ports, snum, &ports->udp);
}

static inline void krgip_local_ports_tcp_add(struct krgip_local_ports *ports,
					     struct krgip_local_port *port)
{
	krgip_local_ports_add(ports, port, &ports->tcp);
}

static inline void krgip_local_ports_tcp_del(struct krgip_local_ports *ports,
					     __be16 snum)
{
	krgip_local_ports_del(ports, snum, &ports->tcp);
}

static inline bool krgip_local_ports_empty(struct krgip_local_ports *ports)
{
	return list_empty(&ports->udp) && list_empty(&ports->tcp);
}

static
inline
struct krgip_local_port *krgip_local_port_find(struct list_head *head, __be16 port)
{
	struct krgip_local_port *pos;

	list_for_each_entry_rcu(pos, head, list)
		if (pos->port == port)
			return pos;
	return NULL;
}

int krgip_cluster_ip_unused(__be32 addr);

void krgip_cluster_ip_put_or_remove(struct kddm_set *set,
				    struct krgip_cluster_ip_kddm_object *obj);

struct krgip_addr *krgip_addr_alloc(__be32 addr);
void krgip_addr_free(struct krgip_addr *addr);

static
inline struct krgip_addr *krgip_addr_find(struct list_head *head, __be32 addr)
{
	struct krgip_addr *pos;

	list_for_each_entry(pos, head, list)
		if (pos->addr == addr)
			return pos;
	return NULL;
}

void
krgip_cluster_port_put_or_remove(struct kddm_set *set,
				 struct krgip_cluster_port_kddm_object *obj);

struct sock;

int
krgip_cluster_ip_tcp_get_port_prepare(struct sock *sk,
				      unsigned short snum,
				      struct krgip_cluster_ip_kddm_object **ip_obj_p,
				      struct krgip_cluster_port_kddm_object **port_obj_p,
				      struct krgip_addr **addr,
				      struct krgip_local_port **port);
void
krgip_cluster_ip_tcp_get_port_finish(struct sock *sk,
				     struct krgip_cluster_ip_kddm_object *ip_obj,
				     struct krgip_cluster_port_kddm_object *port_obj,
				     struct krgip_addr *addr,
				     struct krgip_local_port *port,
				     int error);
void
krgip_cluster_ip_tcp_unhash_prepare(struct sock *sk,
				    struct krgip_cluster_ip_kddm_object **ip_obj_p,
				    struct krgip_cluster_port_kddm_object **port_obj_p);
void
krgip_cluster_ip_tcp_unhash_finish(struct sock *sk,
				   struct krgip_cluster_ip_kddm_object *ip_obj,
				   struct krgip_cluster_port_kddm_object *port_obj);

int krgip_cluster_ip_start(void);

#endif /* __KRG_CLUSTERIP_H__ */
