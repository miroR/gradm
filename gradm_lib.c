#include "gradm.h"

/* anticipatory memory allocator */

/* gr_stat_alloc(): for groups of allocations that need to be done quickly
		    allocate several more of larger size, fit for use as
		    filenames (4k), then hand out one at a time until 
		    there are none left.
   gr_dyn_alloc() : addresses that need constant resizing
		    here we allocate 128 times the amount requested,
		    once this is full, we redirect to the real realloc,
		    and then update our internal structures.
*/

struct mem_entry {
	void *data;
	void *current;
};

struct resize_entry {
	unsigned long max;
};

#define MAX_MEM_SIZE	512
#define MAX_RESIZE_SIZE	16

static struct mem_entry **stat_alloc = NULL;
static unsigned long stat_alloc_num = 0;
static unsigned long stat_alloc_start = 0;

void gr_stat_free_all(void)
{
	unsigned long i;

	for (i = 0; i < stat_alloc_num; i++)
		free(stat_alloc[i]->data);
	if (stat_alloc != NULL)
		free(stat_alloc);
	stat_alloc_num = 0;
	stat_alloc = NULL;
}

void * gr_stat_alloc(unsigned long len)
{
	unsigned long i, j;
	void *ret = NULL;

	if (stat_alloc == NULL) {
		stat_alloc = calloc(MAX_MEM_SIZE, sizeof(struct mem_entry *));
		if (stat_alloc == NULL)
			failure("calloc");
		stat_alloc_num = MAX_MEM_SIZE;

		/* allocate new mem_entries */
		for (j = 0; j < MAX_MEM_SIZE; j++) {
			stat_alloc[j] = calloc(1, sizeof(struct mem_entry));
			if (stat_alloc[j] == NULL)
				failure("calloc");
		}
	}

	for (i = stat_alloc_start; i < stat_alloc_num; i++) {
		if (stat_alloc[i]->data != NULL) {
			if ((stat_alloc[i]->current - stat_alloc[i]->data + len) < (PATH_MAX * MAX_MEM_SIZE)) {
				ret = stat_alloc[i]->current;
				stat_alloc[i]->current = stat_alloc[i]->current + len;
				return ret;
			}
		} else
			break;
	}

	if (i == stat_alloc_num) {
		/* out of space, need to resize allocation list */
		stat_alloc = realloc(stat_alloc, (stat_alloc_num + MAX_MEM_SIZE) * sizeof(struct mem_entry *));
		if (stat_alloc == NULL)
			failure("realloc");
		stat_alloc_num = stat_alloc_num + MAX_MEM_SIZE;
		memset(stat_alloc + MAX_MEM_SIZE, 0, MAX_MEM_SIZE * sizeof(struct mem_entry *));

		/* allocate new mem_entries */
		for (j = 0; j < MAX_MEM_SIZE; j++) {
			stat_alloc[MAX_MEM_SIZE + j] = calloc(1, sizeof(struct mem_entry));
			if (stat_alloc[MAX_MEM_SIZE + j] == NULL)
				failure("calloc");
		}
	}

	/* ->data was null, let's allocate it */
	stat_alloc[i]->data = malloc(PATH_MAX * MAX_MEM_SIZE);
	if (stat_alloc[i]->data == NULL)
		failure("malloc");
	stat_alloc[i]->current = stat_alloc[i]->data + len;
	stat_alloc_start = i;
	ret = stat_alloc[i]->data;

	return ret;
}

void * gr_dyn_alloc(unsigned long len)
{
	void *ret;
	struct resize_entry *resent;

	/* store usage information before the actual allocation. */
	ret = calloc(1, (MAX_RESIZE_SIZE * len) + sizeof(struct resize_entry));
	if (ret == NULL)
		failure("calloc");
	resent = ret;
	resent->max = MAX_RESIZE_SIZE * len;
	ret = ret + sizeof(struct resize_entry);

	return ret;
}

void * gr_dyn_resize(void *addr, unsigned long len)
{
	void *ret = NULL;
	struct resize_entry *resent;

	resent = addr - sizeof(struct resize_entry);
	if (len < resent->max)
		return addr;
	else {
		ret = realloc(resent, (MAX_RESIZE_SIZE * len) + sizeof(struct resize_entry));
		if (ret == NULL)
			failure("relloc");
		resent = ret;
		resent->max = MAX_RESIZE_SIZE * len;
		ret = ret + sizeof(struct resize_entry);
	}

	return ret;		
}

void gr_dyn_free(void *addr)
{
	void *ptr;

	ptr = addr - sizeof(struct resize_entry);
	free(ptr);

	return;
}
