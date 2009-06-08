#ifndef DEBUG_TOOLS_2_H
#define DEBUG_TOOLS_2_H

#include <linux/debugfs.h>
#include <linux/dcache.h>
#include <linux/rbtree.h>

#ifdef CONFIG_KRG_DEBUG

#define KRG_DBG_MAX_SIZE_MODULE_NAME 16
#define KRG_DBG_MAX_NB_MASKS 24
#define KRG_DBG_MAX_SIZE_MASK 16

struct dbg_mask {
	unsigned int val;

	unsigned int nb_masks;
	char mask_name[KRG_DBG_MAX_NB_MASKS][KRG_DBG_MAX_SIZE_MASK];
};

struct debug_level {
	struct rb_node node;
	char keystring[KRG_DBG_MAX_SIZE_MODULE_NAME];

	struct dentry *level_dent;
	unsigned int level_value;

	struct dentry *masks_dent;
	struct dbg_mask masks;

	struct dentry *dent;
	struct dentry *parent;
};

void krg_debugfs_create_dir(struct debug_level *dbg);

void add_debug_mask(struct rb_root *root,
		    const char *module_name,
		    const char *mask_name);

struct debug_level *search_debug_level(struct rb_root *root, const char *string);
int insert_debug_level(struct rb_root *root, struct debug_level *data);

void krg_debugfs_cleanup(struct rb_root *root, struct dentry *droot);

/* ============================================================== */

void debug_init(const char *name);
void debug_cleanup(void);

struct dentry *debug_get_main_dentry(void);
struct rb_root *debug_get_rbroot(void);

/* ============================================================== */

struct dentry *__debug_define(const char *name, int level,
			      struct dentry *parent);

static inline struct dentry *debug_define(const char *name, int level)
{
	return __debug_define (name, level, NULL);
}

#define DEBUG_MASK(module_name, mask_name) \
	add_debug_mask(debug_get_rbroot(), module_name, mask_name)

int match_debug(const char *module, const char *mask, int level);

#else /* CONFIG_KRG_DEBUG */

static inline
void add_debug_mask(struct rb_root *root,
		    const char *module_name,
		    const char *mask_name)
{
}

static inline
struct debug_level *search_debug_level(struct rb_root *root, const char *string)
{
	return NULL;
}

static inline void debug_init(const char *name)
{
}

static inline void debug_cleanup(void)
{
}

static inline struct rb_root *debug_get_rbroot(void)
{
	return NULL;
}

static inline struct dentry *debug_define(const char *name, int level)
{
	return NULL;
}

#define DEBUG_MASK do {} while (0)

static inline int match_debug(const char *module, const char *mask, int level)
{
	return 0;
}

#endif /* CONFIG_KRG_DEBUG */

#endif /* DEBUG_TOOLS_2_H */
