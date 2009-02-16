/*
 * net/tipc/tipc_eth_media.c: Ethernet bearer support for TIPC
 *
 * Copyright (c) 2001-2007, Ericsson AB
 * Copyright (c) 2005-2008, Wind River Systems
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the names of the copyright holders nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") version 2 as published by the Free
 * Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <net/tipc/tipc.h>
#include <net/tipc/tipc_plugin_if.h>
#include <net/tipc/tipc_plugin_msg.h>
#include <linux/netdevice.h>
#include <linux/workqueue.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
#include <net/net_namespace.h>
#endif

#define MAX_ETH_BEARERS		TIPC_MAX_BEARERS
#define ETH_LINK_PRIORITY	TIPC_DEF_LINK_PRI
#define ETH_LINK_TOLERANCE	TIPC_DEF_LINK_TOL

/**
 * struct eth_bearer - Ethernet bearer data structure
 * @bearer: ptr to associated "generic" bearer structure
 * @dev: ptr to associated Ethernet network device
 * @tipc_packet_type: used in binding TIPC to Ethernet driver
 * @cleanup: work item used when disabling bearer
 */

struct eth_bearer {
	struct tipc_bearer *bearer;
	struct net_device *dev;
	struct packet_type tipc_packet_type;
	struct work_struct cleanup;
};

static struct tipc_media eth_media_info;
static struct eth_bearer eth_bearers[MAX_ETH_BEARERS];
static int eth_started = 0;

static struct notifier_block notifier;
static struct work_struct reg_notifier;

/**
 * eth_media_addr_init - initialize Ethernet media address structure
 * 
 * Structure's "value" field stores address info in the following format:
 * - Ethernet media type identifier [4 bytes, in network byte order]
 * - MAC address [6 bytes]
 * - unused [10 bytes of zeroes]
 * 
 * Note: This is the same format as the TIPC neighbour discovery message uses
 * to designate an Ethernet address, which simplies the job of getting the
 * media address into/out of the message header.
 */

static void eth_media_addr_init(struct tipc_media_addr *a, char *mac)
{
	memset(a->value, 0, sizeof(a->value));
	a->value[3] = TIPC_MEDIA_ID_ETH;
	memcpy(&a->value[4], mac, ETH_ALEN);

	a->media_id = TIPC_MEDIA_ID_ETH;
        a->broadcast = !memcmp(mac, &eth_media_info.bcast_addr.value[4], ETH_ALEN);
}

/**
 * send_msg - send a TIPC message out over an Ethernet interface
 */

static int send_msg(struct sk_buff *buf, struct tipc_bearer *tb_ptr,
		    struct tipc_media_addr *dest)
{
	struct sk_buff *clone;
	struct net_device *dev;
	int delta;

	clone = skb_clone(buf, GFP_ATOMIC);
	if (!clone)
		return 0;
	
	dev = ((struct eth_bearer *)(tb_ptr->usr_handle))->dev;
	delta = dev->hard_header_len - skb_headroom(buf);

	if ((delta > 0) && 
	    pskb_expand_head(clone, SKB_DATA_ALIGN(delta), 0, GFP_ATOMIC)) {
		kfree_skb(clone);
		return 0;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
	skb_reset_network_header(clone);
#else
	clone->nh.raw = clone->data;
#endif
	clone->dev = dev;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
	dev_hard_header(clone, dev, ETH_P_TIPC, &dest->value[4],
			dev->dev_addr, clone->len);
#else
	dev->hard_header(clone, dev, ETH_P_TIPC, &dest->value[4],
			 dev->dev_addr, clone->len);
#endif
	dev_queue_xmit(clone);
	return 0;
}

/**
 * recv_msg - handle incoming TIPC message from an Ethernet interface
 *
 * Accept only packets explicitly sent to this node, or broadcast packets;
 * ignores packets sent using Ethernet multicast, and traffic sent to other
 * nodes (which can happen if interface is running in promiscuous mode).
 */

static int recv_msg(struct sk_buff *buf, struct net_device *dev,
		    struct packet_type *pt, struct net_device *orig_dev)
{
	struct eth_bearer *eb_ptr = (struct eth_bearer *)pt->af_packet_priv;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
	if (!net_eq(dev_net(dev), &init_net)) {
		kfree_skb(buf);
		return 0;
	}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
	if (dev_net(dev) != &init_net) {
		kfree_skb(buf);
		return 0;
	}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
	if (dev->nd_net != &init_net) {
		kfree_skb(buf);
		return 0;
	}
#endif

	if (likely(eb_ptr->bearer)) {
		if (likely(buf->pkt_type <= PACKET_BROADCAST)) {
			buf->next = NULL;
			tipc_recv_msg(buf, eb_ptr->bearer);
			return 0;
		}
	}
	kfree_skb(buf);
	return 0;
}

/**
 * enable_bearer - attach TIPC bearer to an Ethernet interface
 */

static int enable_bearer(struct tipc_bearer *tb_ptr)
{
	struct net_device *dev = NULL;
	struct net_device *pdev;
	struct eth_bearer *eb_ptr = &eth_bearers[0];
	struct eth_bearer *stop = &eth_bearers[MAX_ETH_BEARERS];
	char *driver_name = strchr((const char *)tb_ptr->name, ':') + 1;
	int pending_dev = 0;

	/* Find unused Ethernet bearer structure */

	while (eb_ptr->dev) {
		if (!eb_ptr->bearer)
			pending_dev++;
		if (++eb_ptr == stop)
			return pending_dev ? -EAGAIN : -EDQUOT;
	}

	/* Find device with specified name */

	read_lock(&dev_base_lock);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
	for_each_netdev(&init_net, pdev) {
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
	for_each_netdev(pdev) {
#else
	for (pdev = dev_base; pdev; pdev = pdev->next) {
#endif
		if (!strncmp(pdev->name, driver_name, IFNAMSIZ)) {
			dev = pdev;
			dev_hold(dev);
			break;
		}
	}
	read_unlock(&dev_base_lock);
	if (!dev)
		return -ENODEV;

	/* Create Ethernet bearer for device */

	eb_ptr->dev = dev;
	eb_ptr->tipc_packet_type.type = htons(ETH_P_TIPC);
	eb_ptr->tipc_packet_type.dev = dev;
	eb_ptr->tipc_packet_type.func = recv_msg;
	eb_ptr->tipc_packet_type.af_packet_priv = eb_ptr;
	INIT_LIST_HEAD(&(eb_ptr->tipc_packet_type.list));
	dev_add_pack(&eb_ptr->tipc_packet_type);

	/* Associate TIPC bearer with Ethernet bearer */

	eb_ptr->bearer = tb_ptr;
	tb_ptr->usr_handle = (void *)eb_ptr;
	tb_ptr->mtu = dev->mtu;
	tb_ptr->blocked = 0;
	eth_media_addr_init(&tb_ptr->addr, (char *)&dev->dev_addr);

	return 0;
}

/**
 * cleanup_bearer - break association between Ethernet bearer and interface 
 * 
 * This routine must be invoked from a work queue because it can sleep. 
 */

static void cleanup_bearer(struct work_struct *work)
{
	struct eth_bearer *eb_ptr =
		container_of(work, struct eth_bearer, cleanup);

	dev_remove_pack(&eb_ptr->tipc_packet_type);
	dev_put(eb_ptr->dev);
	eb_ptr->dev = NULL;
}

/**
 * disable_bearer - detach TIPC bearer from an Ethernet interface
 *
 * Mark Ethernet bearer as inactive so that incoming buffers are thrown away,
 * then get worker thread to complete bearer cleanup.  (Can't do cleanup
 * here because cleanup code needs to sleep and caller holds spinlocks.)
 */

static void disable_bearer(struct tipc_bearer *tb_ptr)
{
	struct eth_bearer *eb_ptr = (struct eth_bearer *)tb_ptr->usr_handle;

	eb_ptr->bearer = NULL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
	INIT_WORK(&eb_ptr->cleanup, cleanup_bearer);
#else
	INIT_WORK(&eb_ptr->cleanup, (void (*)(void *))cleanup_bearer,
		  &eb_ptr->cleanup);
#endif
	schedule_work(&eb_ptr->cleanup);
}

/**
 * recv_notification - handle device updates from OS
 *
 * Change the state of the Ethernet bearer (if any) associated with the
 * specified device.
 */

static int recv_notification(struct notifier_block *nb, unsigned long evt,
			     void *dv)
{
	struct net_device *dev = (struct net_device *)dv;
	struct eth_bearer *eb_ptr = &eth_bearers[0];
	struct eth_bearer *stop = &eth_bearers[MAX_ETH_BEARERS];

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
	if (!net_eq(dev_net(dev), &init_net))
		return NOTIFY_DONE;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
	if (dev_net(dev) != &init_net)
		return NOTIFY_DONE;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
	if (dev->nd_net != &init_net)
		return NOTIFY_DONE;
#endif

	while ((eb_ptr->dev != dev)) {
		if (++eb_ptr == stop)
			return NOTIFY_DONE;	/* couldn't find device */
	}
	if (!eb_ptr->bearer)
		return NOTIFY_DONE;		/* bearer had been disabled */

	eb_ptr->bearer->mtu = dev->mtu;

	switch (evt) {
	case NETDEV_CHANGE:
		if (netif_carrier_ok(dev))
			tipc_continue(eb_ptr->bearer);
		else
			tipc_block_bearer(eb_ptr->bearer->name);
		break;
	case NETDEV_UP:
		tipc_continue(eb_ptr->bearer);
		break;
	case NETDEV_DOWN:
		tipc_block_bearer(eb_ptr->bearer->name);
		break;
	case NETDEV_CHANGEMTU:
	case NETDEV_CHANGEADDR:
		tipc_block_bearer(eb_ptr->bearer->name);
		tipc_continue(eb_ptr->bearer);
		break;
	case NETDEV_UNREGISTER:
	case NETDEV_CHANGENAME:
		tipc_disable_bearer(eb_ptr->bearer->name);
		break;
	}
	return NOTIFY_OK;
}

static int eth_msg2addr(struct tipc_media_addr *a, u32 *msg_area)
{
	if (msg_area[0] != htonl(TIPC_MEDIA_ID_ETH))
		return 1;

	eth_media_addr_init(a, (char *)&msg_area[1]);
	return 0;
}

static int eth_addr2msg(struct tipc_media_addr *a, u32 *msg_area)
{
	if (a->media_id != TIPC_MEDIA_ID_ETH)
		return 1;

	memcpy(msg_area, a->value, sizeof(a->value));
	return 0;
}

/**
 * eth_addr2str - convert Ethernet address to string
 */

static int eth_addr2str(struct tipc_media_addr *a, char *str_buf, int str_size)
{                       
	unsigned char *mac;

	if ((a->media_id != TIPC_MEDIA_ID_ETH) || (str_size < 18))
		return 1;
		
	mac = (unsigned char *)&a->value[4];
	sprintf(str_buf, "%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return 0;
}


/**
 * eth_str2addr - convert string to Ethernet address
 */

static int eth_str2addr(struct tipc_media_addr *a, char *str_buf)
{                     
	char mac[6];

        if (ETH_ALEN != sscanf(str_buf, "%02x:%02x:%02x:%02x:%02x:%02x",
                               (u32 *)&mac[0], (u32 *)&mac[1], (u32 *)&mac[2],
                               (u32 *)&mac[3], (u32 *)&mac[4], (u32 *)&mac[5]))
            return 1;

	eth_media_addr_init(a, mac);
        return 0;
}

/*
 * Ethernet media registration info required by TIPC
 */

static struct tipc_media eth_media_info = {
	TIPC_MEDIA_ID_ETH,
	"eth",
	ETH_LINK_PRIORITY,
	ETH_LINK_TOLERANCE,
	TIPC_DEF_LINK_WIN,
	send_msg,
	enable_bearer,
	disable_bearer,
	eth_addr2str,
	eth_str2addr,
        eth_msg2addr,
        eth_addr2msg,
	{{0, 0, 0, TIPC_MEDIA_ID_ETH, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	TIPC_MEDIA_ID_ETH, 1}
};

/**
 * do_registration - register TIPC to receive device notifications
 * 
 * This routine must be invoked from a work queue because it can sleep. 
 */

static void do_registration(struct work_struct *dummy)
{
	notifier.notifier_call = &recv_notification;
	notifier.priority = 0;
	register_netdevice_notifier(&notifier);
}

/**
 * tipc_eth_media_start - activate Ethernet bearer support
 *
 * Register Ethernet media type with TIPC bearer code.
 * Also register with OS for notifications about device state changes.
 */

int tipc_eth_media_start(void)
{                       
	int res;

	if (eth_started)
		return -EINVAL;

	memset(eth_bearers, 0, sizeof(eth_bearers));

	res = tipc_register_media(&eth_media_info);
	if (res)
		return res;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
	INIT_WORK(&reg_notifier, do_registration);
#else
	INIT_WORK(&reg_notifier, (void (*)(void *))do_registration, NULL);
#endif
	schedule_work(&reg_notifier);
	eth_started = 1;
	return res;
}

/**
 * tipc_eth_media_stop - deactivate Ethernet bearer support
 */

void tipc_eth_media_stop(void)
{
	if (!eth_started)
		return;

	flush_scheduled_work();
	unregister_netdevice_notifier(&notifier);
	eth_started = 0;
}
