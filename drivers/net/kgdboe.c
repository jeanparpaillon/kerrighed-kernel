/*
 * drivers/net/kgdboe.c
 *
 * A network interface for GDB.
 * Based upon 'gdbserial' by David Grothe <dave@gcom.com>
 * and Scott Foehner <sfoehner@engr.sgi.com>
 *
 * Maintainer: Jason Wessel <jason.wessel@windriver.com>
 *
 * 2004 (c) Amit S. Kale <amitkale@linsyssoft.com>
 * 2004-2005 (c) MontaVista Software, Inc.
 * 2005-2008 (c) Wind River Systems, Inc.
 *
 * Contributors at various stages not listed above:
 * San Mehat <nettwerk@biodome.org>, Robert Walsh <rjwalsh@durables.org>,
 * wangdi <wangdi@clusterfs.com>, Matt Mackall <mpm@selenic.com>,
 * Pavel Machek <pavel@suse.cz>, Jason Wessel <jason.wessel@windriver.com>
 *
 * This file is licensed under the terms of the GNU General Public License
 * version 2. This program is licensed "as is" without any warranty of any
 * kind, whether express or implied.
 */

#include <linux/kernel.h>
#include <linux/interrupt.h>
#include <linux/string.h>
#include <linux/kgdb.h>
#include <linux/netpoll.h>
#include <linux/init.h>

#include <asm/atomic.h>

#define IN_BUF_SIZE 512		/* power of 2, please */
#define OUT_BUF_SIZE 30		/* We don't want to send too big of a packet. */
#define MAX_CONFIG_LEN 256

static char in_buf[IN_BUF_SIZE], out_buf[OUT_BUF_SIZE];
static int in_head, in_tail, out_count;
static atomic_t in_count;
/* 0 = unconfigured, 1 = netpoll options parsed, 2 = fully configured. */
static int configured;
static struct kgdb_io local_kgdb_io_ops;
static int use_dynamic_mac;

MODULE_DESCRIPTION("KGDB driver for network interfaces");
MODULE_LICENSE("GPL");
static char config[MAX_CONFIG_LEN];
static struct kparam_string kps = {
	.string = config,
	.maxlen = MAX_CONFIG_LEN,
};

static void rx_hook(struct netpoll *np, int port, char *msg, int len,
		    struct sk_buff *skb)
{
	int i;

	np->remote_port = port;

	/* Copy the MAC address if we need to. */
	if (use_dynamic_mac) {
		memcpy(np->remote_mac, eth_hdr(skb)->h_source,
				sizeof(np->remote_mac));
		use_dynamic_mac = 0;
	}

	/*
	 * This could be GDB trying to attach.  But it could also be GDB
	 * finishing up a session, with kgdb_connected=0 but GDB sending
	 * an ACK for the final packet.  To make sure we don't try and
	 * make a breakpoint when GDB is leaving, make sure that if
	 * !kgdb_connected the only len == 1 packet we allow is ^C.
	 */
	if (!kgdb_connected && (len != 1 || msg[0] == 3))
		kgdb_schedule_breakpoint();

	for (i = 0; i < len; i++) {
		if (msg[i] == 3)
			kgdb_schedule_breakpoint();

		if (atomic_read(&in_count) >= IN_BUF_SIZE) {
			/* buffer overflow, clear it */
			in_head = 0;
			in_tail = 0;
			atomic_set(&in_count, 0);
			break;
		}
		in_buf[in_head++] = msg[i];
		in_head &= (IN_BUF_SIZE - 1);
		atomic_inc(&in_count);
	}
}

static struct netpoll np = {
	.dev_name = "eth0",
	.name = "kgdboe",
	.rx_hook = rx_hook,
	.local_port = 6443,
	.remote_port = 6442,
	.remote_mac = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
};

static void eth_pre_exception_handler(void)
{
	/* Increment the module count when the debugger is active */
	if (!kgdb_connected)
		try_module_get(THIS_MODULE);
	netpoll_set_trap(1);
}

static void eth_post_exception_handler(void)
{
	/* decrement the module count when the debugger detaches */
	if (!kgdb_connected)
		module_put(THIS_MODULE);
	netpoll_set_trap(0);
}

static int eth_get_char(void)
{
	int chr;

	while (atomic_read(&in_count) == 0)
		netpoll_poll(&np);

	chr = in_buf[in_tail++];
	in_tail &= (IN_BUF_SIZE - 1);
	atomic_dec(&in_count);
	return chr;
}

static void eth_flush_buf(void)
{
	if (out_count && np.dev) {
		netpoll_send_udp(&np, out_buf, out_count);
		memset(out_buf, 0, sizeof(out_buf));
		out_count = 0;
	}
}

static void eth_put_char(u8 chr)
{
	out_buf[out_count++] = chr;
	if (out_count == OUT_BUF_SIZE)
		eth_flush_buf();
}

static int option_setup(char *opt)
{
	char opt_scratch[MAX_CONFIG_LEN];

	configured = 0;
	/* If we're being given a new configuration, copy it in. */
	if (opt != config)
		strcpy(config, opt);

	if (opt[0] == '\0')
		return 1;

	/* But work on a copy as netpoll_parse_options will eat it. */
	strcpy(opt_scratch, opt);
	configured = !netpoll_parse_options(&np, opt_scratch);

	use_dynamic_mac = 1;

	return 0;
}
__setup("kgdboe=", option_setup);

/* With our config string set by some means, configure kgdboe. */
static int configure_kgdboe(void)
{
	if (option_setup(config))
		return 0;

	if (!configured) {
		printk(KERN_ERR "kgdboe: configuration incorrect - kgdboe not "
		       "loaded.\n");
		printk(KERN_ERR "  Usage: kgdboe=[src-port]@[src-ip]/[dev],"
				"[tgt-port]@<tgt-ip>/<tgt-macaddr>\n");
		return -EINVAL;
	}

	/* Bring it up. */
	if (netpoll_setup(&np)) {
		printk(KERN_ERR "kgdboe: netpoll_setup failed kgdboe failed\n");
		return -EINVAL;
	}

	if (kgdb_register_io_module(&local_kgdb_io_ops)) {
		netpoll_cleanup(&np);
		return -EINVAL;
	}

	configured = 2;

	return 0;
}

static int init_kgdboe(void)
{
	int ret;

	/* Already done? */
	if (configured == 2)
		return 0;

	/* OK, go ahead and do it. */
	ret = configure_kgdboe();

	if (configured == 2)
		printk(KERN_INFO "kgdboe: debugging over ethernet enabled\n");

	return ret;
}

static void cleanup_kgdboe(void)
{
	netpoll_cleanup(&np);
	configured = 0;
	kgdb_unregister_io_module(&local_kgdb_io_ops);
}

static int param_set_kgdboe_var(const char *kmessage, struct kernel_param *kp)
{
	char kmessage_save[MAX_CONFIG_LEN];
	int len = strlen(kmessage);

	if (len >= MAX_CONFIG_LEN) {
		printk(KERN_ERR "kgdboc: config string too long\n");
		return -ENOSPC;
	}

	if (kgdb_connected) {
		printk(KERN_ERR "kgdboe: Cannot reconfigure while KGDB is "
				"connected.\n");
		return 0;
	}

	/* Start the reconfiguration process by saving the old string */
	strncpy(kmessage_save, config, sizeof(kmessage_save));


	/* Copy in the new param and strip out invalid characters so we
	 * can optionally specify the MAC.
	 */
	strcpy(config, kmessage);
	/* Chop out \n char as a result of echo */
	if (config[len - 1] == '\n')
		config[len - 1] = '\0';

	len--;
	while (len > 0 && (config[len] < ',' || config[len] > 'f')) {
		config[len] = '\0';
		len--;
	}

	if (configured == 2) {
		cleanup_kgdboe();
		configured = 0;
	}
	if (config[0] == '\0')
		return 0;

	configure_kgdboe();

	if (configured != 2)
		return -EINVAL;

	return 0;
}

static struct kgdb_io local_kgdb_io_ops = {
	.name = "kgdboe",
	.read_char = eth_get_char,
	.write_char = eth_put_char,
	.flush = eth_flush_buf,
	.pre_exception = eth_pre_exception_handler,
	.post_exception = eth_post_exception_handler
};

module_init(init_kgdboe);
module_exit(cleanup_kgdboe);
module_param_call(kgdboe, param_set_kgdboe_var, param_get_string, &kps, 0644);
MODULE_PARM_DESC(kgdboe, "[src-port]@[src-ip]/[dev],"
		 "[tgt-port]@<tgt-ip>/<tgt-macaddr>");
