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

void * gr_dyn_realloc(void *addr, unsigned long len)
{
	void *ret = NULL;
	struct resize_entry *resent;

	if (addr == NULL)
		return gr_dyn_alloc(len);

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

unsigned long table_sizes[] = {
	13, 31, 61, 127, 251, 509, 1021, 2039, 4093, 8191, 16381,
	32749, 65521, 131071, 262139, 524287, 1048573, 2097143,
	4194301, 8388593, 16777213, 33554393, 67108859, 134217689,
	268435399, 536870909, 1073741789, 2147483647
};

static __inline__ unsigned long
fhash(const unsigned long ino, const unsigned int dev, const unsigned long sz)
{
	return (((ino + dev) ^ ((ino << 13) + (ino << 23) + (dev << 9))) % sz);
}

/* Name hashing routines. Initial hash value */
/* Hash courtesy of the R5 hash in reiserfs modulo sign bits */
#define init_name_hash()                0

/* partial hash update function. Assume roughly 4 bits per character */
static __inline__ unsigned long partial_name_hash(unsigned long c, 
unsigned long prevhash)
{
	return (prevhash + (c << 4) + (c >> 4)) * 11;
}

/* Finally: cut down the number of bits to a int value (and try to avoid losing bits) */
static __inline__ unsigned long end_name_hash(unsigned long hash)
{
	return (unsigned int) hash;
}

/* Compute the hash for a name string. */
static __inline__ unsigned int full_name_hash(const unsigned char * name)
{
	unsigned long hash = init_name_hash();
	while (*name != '\0')
		hash = partial_name_hash(*name++, hash);
	return end_name_hash(hash);
}

static __inline__ unsigned long
nhash(const char *name, const unsigned long sz)
{
	return full_name_hash(name) % sz;
}

void insert_hash_entry(struct gr_hash_struct *hash, void *entry);
void insert_name_entry(struct gr_hash_struct *hash, void *entry);

void resize_hash_table(struct gr_hash_struct *hash)
{
	unsigned long i;
	struct gr_hash_struct newhash;

	for (i = 0; i < sizeof(table_sizes)/sizeof(table_sizes[0]); i++) {
		if (table_sizes[i] > hash->table_size) {
			newhash.table_size = table_sizes[i];
			break;
		}
	}

	if (newhash.table_size == 0) {
		fprintf(stderr, "Out of memory.\n");
		exit(EXIT_FAILURE);
	}

	newhash.table = calloc(newhash.table_size, sizeof(void *));
	if (newhash.table == NULL)
		failure("calloc");

	if (hash->type != GR_HASH_FILENAME) {
		newhash.nametable = calloc(newhash.table_size, sizeof(void *));
		if (newhash.nametable == NULL)
			failure("calloc");
	}

	newhash.used_size = 0;
	newhash.type = hash->type;
	newhash.first = hash->first;
	
	for (i = 0; i < hash->table_size; i++)
		if (hash->table[i]) {
			insert_hash_entry(&newhash, hash->table[i]);
			insert_name_entry(&newhash, hash->table[i]);
		}

	free(hash->table);
	if (hash->nametable)
		free(hash->nametable);
	memcpy(hash, &newhash, sizeof(newhash));

	return;
}

void *lookup_name_entry(struct gr_hash_struct *hash, char *name)
{
	if (hash == NULL)
		return NULL;
	if (hash->type == GR_HASH_OBJECT) {
		unsigned long index = nhash(name, hash->table_size);
		struct file_acl *match;
		unsigned char i = 0;

		match = (struct file_acl *)hash->nametable[index];

		while (match && strcmp(match->filename, name)) {
			index = (index + (1 << i)) % hash->table_size;
			match = (struct file_acl *)hash->nametable[index];
			i = (i + 1) % 32;
		}

		return match;
	} else if (hash->type == GR_HASH_SUBJECT) {
		unsigned long index = nhash(name, hash->table_size);
		struct proc_acl *match;
		unsigned char i = 0;

		match = (struct proc_acl *)hash->nametable[index];

		while (match && strcmp(match->filename, name)) {
			index = (index + (1 << i)) % hash->table_size;
			match = (struct proc_acl *)hash->nametable[index];
			i = (i + 1) % 32;
		}

		return match;
	}
	return NULL;
}

struct file_acl *lookup_acl_object_by_name(struct proc_acl *subject, char *name)
{
	return (struct file_acl *)lookup_name_entry(subject->hash, name);
}

struct proc_acl *lookup_acl_subject_by_name(struct role_acl *role, char *name)
{
	return (struct proc_acl *)lookup_name_entry(role->hash, name);
}

void *lookup_hash_entry(struct gr_hash_struct *hash, void *entry)
{
	if (hash == NULL)
		return NULL;

	if (hash->type == GR_HASH_OBJECT) {
		struct file_acl *object = (struct file_acl *)entry;
		unsigned long index = fhash(object->inode, object->dev, hash->table_size);
		struct file_acl *match;
		unsigned char i = 0;

		match = (struct file_acl *)hash->table[index];

		while (match && (match->inode != object->inode ||
		       match->dev != object->dev)) {
			index = (index + (1 << i)) % hash->table_size;
			match = (struct file_acl *)hash->table[index];
			i = (i + 1) % 32;
		}

		return match;
	} else if (hash->type == GR_HASH_SUBJECT) {
		struct proc_acl *subject = (struct proc_acl *)entry;
		unsigned long index = fhash(subject->inode, subject->dev, hash->table_size);
		struct proc_acl *match;
		unsigned char i = 0;

		match = (struct proc_acl *)hash->table[index];

		while (match && (match->inode != subject->inode ||
		       match->dev != subject->dev)) {
			index = (index + (1 << i)) % hash->table_size;
			match = (struct proc_acl *)hash->table[index];
			i = (i + 1) % 32;
		}

		return match;
	} else if (hash->type == GR_HASH_FILENAME) {
		char *filename = (char *)entry;
		unsigned long index = nhash(filename, hash->table_size);
		struct gr_learn_file_tmp_node *match;
		unsigned char i = 0;

		match = (struct gr_learn_file_tmp_node *)hash->table[index];

		while (match && strcmp(match->filename, filename)) {
			index = (index + (1 << i)) % hash->table_size;
			match = (struct gr_learn_file_tmp_node *)hash->table[index];
			i = (i + 1) % 32;
		}

		return match;
	}
	return NULL;
}

struct file_acl *lookup_acl_object(struct proc_acl *subject, struct file_acl *object)
{
	return (struct file_acl *)lookup_hash_entry(subject->hash, object);
}

struct gr_learn_file_tmp_node *lookup_learn_object(struct gr_learn_file_node *subject, char *filename)
{
	return (struct gr_learn_file_tmp_node *)lookup_hash_entry(subject->hash, filename);
}

struct gr_learn_file_tmp_node *lookup_learn_role_subject(struct gr_learn_role_entry *role, char *filename)
{
	return (struct gr_learn_file_tmp_node *)lookup_hash_entry(role->hash, filename);
}

struct gr_learn_file_tmp_node *lookup_learn_group_subject(struct gr_learn_group_node *role, char *filename)
{
	return (struct gr_learn_file_tmp_node *)lookup_hash_entry(role->hash, filename);
}

struct gr_learn_file_tmp_node *lookup_learn_user_subject(struct gr_learn_user_node *role, char *filename)
{
	return (struct gr_learn_file_tmp_node *)lookup_hash_entry(role->hash, filename);
}

struct proc_acl *lookup_acl_subject(struct role_acl *role, struct proc_acl *subject)
{
	return (struct proc_acl *)lookup_hash_entry(role->hash, subject);
}


void insert_name_entry(struct gr_hash_struct *hash, void *entry)
{
	if (hash->type == GR_HASH_OBJECT) {
		struct file_acl *object = (struct file_acl *)entry;
		unsigned long index = nhash(object->filename, hash->table_size);
		struct file_acl **curr;
		unsigned char i = 0;

		curr = (struct file_acl **)&hash->nametable[index];

		while (*curr) {
			index = (index + (1 << i)) % hash->table_size;
			curr = (struct file_acl **)&hash->nametable[index];
			i = (i + 1) % 32;
		}

		*curr = (struct file_acl *)entry;
	} else if (hash->type == GR_HASH_SUBJECT) {
		struct proc_acl *subject = (struct proc_acl *)entry;
		unsigned long index = nhash(subject->filename, hash->table_size);
		struct proc_acl **curr;
		unsigned char i = 0;

		curr = (struct proc_acl **)&hash->nametable[index];

		while (*curr) {
			index = (index + (1 << i)) % hash->table_size;
			curr = (struct proc_acl **)&hash->nametable[index];
			i = (i + 1) % 32;
		}

		*curr = (struct proc_acl *)entry;
	}		
}

void insert_hash_entry(struct gr_hash_struct *hash, void *entry)
{
	/* resize if we're over 50% full */
	if ((hash->used_size + 1) > (hash->table_size / 2))
		resize_hash_table(hash);

	if (hash->type == GR_HASH_OBJECT) {
		struct file_acl *object = (struct file_acl *)entry;
		unsigned long index = fhash(object->inode, object->dev, hash->table_size);
		struct file_acl **curr;
		unsigned char i = 0;

		curr = (struct file_acl **)&hash->table[index];

		while (*curr) {
			index = (index + (1 << i)) % hash->table_size;
			curr = (struct file_acl **)&hash->table[index];
			i = (i + 1) % 32;
		}

		*curr = (struct file_acl *)entry;
		insert_name_entry(hash, *curr);
		hash->used_size++;
	} else if (hash->type == GR_HASH_SUBJECT) {
		struct proc_acl *subject = (struct proc_acl *)entry;
		unsigned long index = fhash(subject->inode, subject->dev, hash->table_size);
		struct proc_acl **curr;
		unsigned char i = 0;

		curr = (struct proc_acl **)&hash->table[index];

		while (*curr) {
			index = (index + (1 << i)) % hash->table_size;
			curr = (struct proc_acl **)&hash->table[index];
			i = (i + 1) % 32;
		}

		*curr = (struct proc_acl *)entry;
		insert_name_entry(hash, *curr);
		hash->used_size++;
	} else if (hash->type == GR_HASH_FILENAME) {
		struct gr_learn_file_tmp_node *node = (struct gr_learn_file_tmp_node *)entry;
		unsigned long index = nhash(node->filename, hash->table_size);
		struct gr_learn_file_tmp_node **curr;
		unsigned char i = 0;

		curr = (struct gr_learn_file_tmp_node **)&hash->table[index];

		while (*curr && !strcmp(node->filename, (*curr)->filename)) {
			index = (index + (1 << i)) % hash->table_size;
			curr = (struct gr_learn_file_tmp_node **)&hash->table[index];
			i = (i + 1) % 32;
		}

		if (*curr)
			(*curr)->mode |= node->mode;
		else {
			*curr = (struct gr_learn_file_tmp_node *)entry;
			hash->used_size++;
		}
	}
}

struct gr_hash_struct *create_hash_table(int type)
{
	struct gr_hash_struct *hash;

	hash = calloc(1, sizeof(struct gr_hash_struct));
	if (hash == NULL)
		failure("calloc");
	hash->table = calloc(table_sizes[0], sizeof(void *));
	if (hash->table == NULL)
		failure("calloc");
	if (type != GR_HASH_FILENAME) {
		hash->nametable = calloc(table_sizes[0], sizeof(void *));
		if (hash->nametable == NULL)
			failure("calloc");
	}
	hash->table_size = table_sizes[0];
	hash->type = type;

	return hash;
}

void insert_learn_object(struct gr_learn_file_tmp_node *subject, struct gr_learn_file_tmp_node *object)
{
	if (subject->hash == NULL)
		subject->hash = create_hash_table(GR_HASH_FILENAME);
	insert_hash_entry(subject->hash, object);
}

void insert_learn_role_subject(struct gr_learn_role_entry *role, struct gr_learn_file_tmp_node *subject)
{
	if (role->hash == NULL)
		role->hash = create_hash_table(GR_HASH_FILENAME);
	insert_hash_entry(role->hash, subject);
}

void insert_learn_group_subject(struct gr_learn_group_node *role, struct gr_learn_file_tmp_node *subject)
{
	if (role->hash == NULL)
		role->hash = create_hash_table(GR_HASH_FILENAME);
	insert_hash_entry(role->hash, subject);
}

void insert_learn_user_subject(struct gr_learn_user_node *role, struct gr_learn_file_tmp_node *subject)
{
	if (role->hash == NULL)
		role->hash = create_hash_table(GR_HASH_FILENAME);
	insert_hash_entry(role->hash, subject);
}

void insert_acl_object(struct proc_acl *subject, struct file_acl *object)
{
	if (subject->hash->first == NULL) {
		subject->hash->first = object;
	} else {
		((struct file_acl *)subject->hash->first)->next = object;
		object->prev = subject->hash->first;
		subject->hash->first = object;
	}

	insert_hash_entry(subject->hash, object);

	return;
}

void insert_acl_subject(struct role_acl *role, struct proc_acl *subject)
{
	if (role->hash == NULL) {
		/* create object hash table */
		role->hash = create_hash_table(GR_HASH_SUBJECT);
		role->hash->first = subject;
	} else {
		((struct proc_acl *)role->hash->first)->next = subject;
		subject->prev = role->hash->first;
		role->hash->first = subject;
	}
	/* force every subject to have a hash table whether or not they
	   have any objects */
	subject->hash = create_hash_table(GR_HASH_OBJECT);
	insert_hash_entry(role->hash, subject);

	return;
}

