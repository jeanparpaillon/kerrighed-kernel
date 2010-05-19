#ifndef LINUX_MM_INLINE_H
#define LINUX_MM_INLINE_H

/**
 * page_is_file_cache - should the page be on a file LRU or anon LRU?
 * @page: the page to test
 *
 * Returns LRU_FILE if @page is page cache page backed by a regular filesystem,
 * or 0 if @page is anonymous, tmpfs or otherwise ram or swap backed.
 * Used by functions that manipulate the LRU lists, to sort a page
 * onto the right LRU list.
 *
 * We would like to get this info without a page flag, but the state
 * needs to survive until the page is last deleted from the LRU, which
 * could be as far down as __page_cache_release.
 */
static inline int page_is_file_cache(struct page *page)
{
	if (PageSwapBacked(page))
		return 0;

	/* The page is page cache backed by a normal filesystem. */
	return LRU_FILE;
}

#ifdef CONFIG_KRG_MM
static inline int page_is_migratable(struct page *page)
{
	if (PageMigratable(page))
		return LRU_MIGR;

	return 0;
}
#endif

static inline void
add_page_to_lru_list(struct zone *zone, struct page *page, enum lru_list l)
{
	list_add(&page->lru, &zone->lru[l].list);
	__inc_zone_state(zone, NR_LRU_BASE + l);
	mem_cgroup_add_lru_list(page, l);
}

static inline void
del_page_from_lru_list(struct zone *zone, struct page *page, enum lru_list l)
{
	list_del(&page->lru);
	__dec_zone_state(zone, NR_LRU_BASE + l);
	mem_cgroup_del_lru_list(page, l);
}

static inline void
del_page_from_lru(struct zone *zone, struct page *page)
{
	enum lru_list l = LRU_BASE;

	list_del(&page->lru);
	if (PageUnevictable(page)) {
		__ClearPageUnevictable(page);
		l = LRU_UNEVICTABLE;
	} else {
		if (PageActive(page)) {
			__ClearPageActive(page);
			l += LRU_ACTIVE;
		}
#ifdef CONFIG_KRG_MM
		if (PageMigratable(page))
			l += LRU_MIGR;
		else
#endif
		l += page_is_file_cache(page);
	}
	__dec_zone_state(zone, NR_LRU_BASE + l);
	mem_cgroup_del_lru_list(page, l);
}

/**
 * page_lru - which LRU list should a page be on?
 * @page: the page to test
 *
 * Returns the LRU list a page should be on, as an index
 * into the array of LRU lists.
 */
static inline enum lru_list page_lru(struct page *page)
{
	enum lru_list lru = LRU_BASE;

	if (PageUnevictable(page))
		lru = LRU_UNEVICTABLE;
	else {
		if (PageActive(page))
			lru += LRU_ACTIVE;
#ifdef CONFIG_KRG_MM
		if (PageMigratable(page))
			lru += LRU_MIGR;
		else
#endif
		lru += page_is_file_cache(page);
	}

	return lru;
}

#define BUILD_LRU_ID(active,file,kddm) (LRU_BASE + LRU_MIGR * kddm + LRU_FILE * file + active)

#ifdef CONFIG_KRG_MM
#define RECLAIM_STAT_INDEX(file,kddm) ((!!file) + 2 * (!!kddm))
static inline int reclaim_stat_index(struct page *page)
{
	return RECLAIM_STAT_INDEX(page_is_file_cache(page),
				  page_is_migratable(page));
}
#endif

#endif
