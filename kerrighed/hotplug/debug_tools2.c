#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/module.h>
#include <kerrighed/debug_tools2.h>

static struct dentry* main_debug_dir = NULL;
static struct rb_root debug_tree = RB_ROOT;

void debug_init(const char* name)
{
	main_debug_dir = debugfs_create_dir(name, NULL);
}

void debug_cleanup(void)
{
	krg_debugfs_cleanup(&debug_tree, main_debug_dir);
}

struct dentry* debug_get_main_dentry(void)
{
	return main_debug_dir;
}

struct rb_root * debug_get_rbroot(void)
{
	return &debug_tree;
}
EXPORT_SYMBOL(debug_get_rbroot);

/* ====================================== */
/* fops for /debug/kerrighed/<MODULE>/level */

static int krg_debugfs_level_set(void *data, u64 val)
{
	if (val < 0) {
		*(int *)data = 0;
	} else if (val > 5) {
		*(int *)data = 5;
	} else {
		*(int *)data = val;
	}
	printk("Set value (%d) : %d\n", (int)val, *(int *)data);
	return 0;
}

static int krg_debugfs_level_get(void *data, u64 *val)
{
	*val = *(int *)data;
	return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(fops_level, krg_debugfs_level_get,
			krg_debugfs_level_set, "%llu\n");

/* ====================================== */
/* fops for /debug/kerrighed/<MODULE>/masks */

static ssize_t read_file_masks(struct file *file, char __user *user_buf,
			       size_t count, loff_t *ppos)
{
	char buffer[1024];
	char line_buffer[64];
	int i, len;
	struct dbg_mask * mask = file->private_data;

	if (!mask)
		return -EFAULT;

	snprintf(buffer, 64, "%18s: 0x%x\n", "ALL", mask->val);

	for (i=0; i<mask->nb_masks; i++) {
		if (mask->val & (1 << i))
			len = snprintf(line_buffer, 64, "%18s: 1 (0x%x)\n",
				       mask->mask_name[i], (1 << i));
		else
			len = snprintf(line_buffer, 64, "%18s: 0 (0x%x)\n",
				       mask->mask_name[i], (1 << i));

		if (len > 0 && strlen(buffer) + strlen(line_buffer) + 1 < 1024)
			strcat(buffer, line_buffer);
		else
			printk("debug_tools2.c:read_file_masks : buffer is too "
			       "small for all your debug masks, you must "
			       "increase the buffer size\n");
	}

	return simple_read_from_buffer(user_buf, count, ppos, buffer, strlen(buffer));
}


static ssize_t write_file_masks(struct file *file, const char __user *user_buf,
				size_t count, loff_t *ppos)
{
	char buf[32];
	int buf_size, len, i, match=0;
	struct dbg_mask * mask = file->private_data;

	if (!mask)
		return -EFAULT;

	buf_size = min(count, (sizeof(buf)-1));
	if (copy_from_user(buf, user_buf, buf_size))
		return -EFAULT;

	if (buf_size >= 6 && strncmp(buf, "ALL:", 4) == 0) {
		char **endp = NULL;
		mask->val = simple_strtoul(&(buf[4]), endp, 0);

		match=1;
	} else {

		/* check that format is "mask:[0|1]\0" */
		if (buf_size < 4 || buf[buf_size-3] != ':' ||
		    (buf[buf_size-2] != '0' && buf[buf_size-2] != '1'))
			return -EINVAL;

		len = min(buf_size-3, KRG_DBG_MAX_SIZE_MASK-1);

		for (i=0; i < mask->nb_masks; i++) {
			if (strlen(mask->mask_name[i]) == len &&
			    strncmp(buf, mask->mask_name[i], len) == 0) {
				match=1;

				if (buf[buf_size-2] == '0' && (mask->val & (1 << i)))
					mask->val -= (1 << i);
				else if (buf[buf_size-2] == '1' && !(mask->val & (1 << i)))
					mask->val += (1 << i);

				break;
			}
		}
	}

	if (!match)
		return -EINVAL;

	return count;
}

static int default_open(struct inode *inode, struct file *file)
{
	if (inode->i_private)
		file->private_data = inode->i_private;

	return 0;
}

static const struct file_operations fops_masks = {
	.read =         read_file_masks,
	.write =        write_file_masks,
	.open =         default_open
};


/* ======================================================== */


void krg_debugfs_create_dir(struct debug_level* dbg)
{
	dbg->dent = debugfs_create_dir(dbg->keystring, dbg->parent);
	if (dbg->dent) {
		dbg->level_dent = debugfs_create_file("level", S_IRWXU,
						      dbg->dent,
						      &(dbg->level_value),
						      &fops_level);
		dbg->masks_dent = debugfs_create_file("masks", S_IRWXU,
						      dbg->dent,
						      &(dbg->masks),
						      &fops_masks);
	}
}

void krg_debugfs_cleanup(struct rb_root *root, struct dentry *droot)
{
	struct rb_node *node, *tmp_node;
	struct debug_level * dbg;

	node = rb_first(root);
	while (node) {
		tmp_node = node;
		node = rb_next(node);
		dbg = container_of(tmp_node, struct debug_level, node);
		rb_erase(tmp_node, root);
		debugfs_remove(dbg->level_dent);
		debugfs_remove(dbg->masks_dent);
		debugfs_remove(dbg->dent);
		kfree(dbg);
	}

	debugfs_remove(droot);
}

void add_debug_mask(struct rb_root *root, const char* module_name,
		    const char* mask_name)
{
	struct debug_level *dbg = search_debug_level(root, module_name);
	if (dbg) {
		struct dbg_mask *dbg_m = &(dbg->masks);
		if (dbg_m->nb_masks < KRG_DBG_MAX_NB_MASKS) {
			snprintf(dbg_m->mask_name[dbg_m->nb_masks],
				 KRG_DBG_MAX_SIZE_MASK, "%s", mask_name);
			dbg_m->nb_masks++;

			if (strlen(mask_name) > KRG_DBG_MAX_SIZE_MASK-1)
				printk("KRG-DEBUG WARNING - debug mask %s "
				       "truncated to %s\n", mask_name,
				       dbg_m->mask_name[dbg_m->nb_masks-1]);
		} else
			printk("KRG-DEBUG ERROR - adding debug mask %s: "
			       "too many debug masks in %s\n",
			       mask_name, module_name);
	}
}
EXPORT_SYMBOL(add_debug_mask);

/* ======================================================== */

struct debug_level *search_debug_level(struct rb_root *root, const char *string)
{
	struct rb_node *node = root->rb_node;

	while (node) {
		struct debug_level *data = container_of(node,
							struct debug_level,
							node);
		int result;

		result = strncmp(string, data->keystring, KRG_DBG_MAX_SIZE_MODULE_NAME-1);

		if (result < 0) node = node->rb_left;
		else if (result > 0) node = node->rb_right;
		else return data;
	}
	return NULL;
}
EXPORT_SYMBOL(search_debug_level);

int insert_debug_level(struct rb_root *root, struct debug_level *data)
{
	struct rb_node **new = &(root->rb_node), *parent = NULL;

	/* Figure out where to put new node */
	while (*new) {
		struct debug_level *this = container_of(*new, struct debug_level, node);
		int result = strcmp(data->keystring, this->keystring);

		parent = *new;
		if (result < 0) new = &((*new)->rb_left);
		else if (result > 0) new = &((*new)->rb_right);
		else return 0;
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&(data->node), parent, new);
	rb_insert_color(&(data->node), root);

	return 1;
}

/* ======================================================== */

int match_debug(const char* module, const char* mask, int level)
{
	struct debug_level * dbg = search_debug_level(debug_get_rbroot(),
						      module);
	if (dbg && dbg->level_value>=level)
	{
		int i;
		for (i=0; i < dbg->masks.nb_masks; i++) {
			if (strncmp(dbg->masks.mask_name[i], mask,
				    KRG_DBG_MAX_SIZE_MASK-1) == 0) {
				if (dbg->masks.val & (1 << i))
					return 1;
				break;
			}
		}
	}
	return 0;
}
EXPORT_SYMBOL(match_debug);

struct dentry * __debug_define(const char* name,
			       int level,
			       struct dentry *parent)
{
	struct debug_level* dbg = kmalloc(sizeof(struct debug_level),
					  GFP_KERNEL);
	snprintf(dbg->keystring, KRG_DBG_MAX_SIZE_MASK, "%s", name);
	dbg->dent = NULL;
	dbg->level_value = level;
	if (parent == NULL)
		dbg->parent = debug_get_main_dentry();
	else
		dbg->parent = parent;
	dbg->masks.val = 0;
	dbg->masks.nb_masks = 0;
	krg_debugfs_create_dir(dbg);
	if (dbg->dent) {
		if (!insert_debug_level(debug_get_rbroot(), dbg)) {
			debugfs_remove(dbg->dent);
			kfree(dbg);
			return NULL;
		}
	} else {
		kfree(dbg);
		return NULL;
	}
	return dbg->dent;
}
EXPORT_SYMBOL(__debug_define);
