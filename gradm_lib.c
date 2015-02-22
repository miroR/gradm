/*
 * Copyright (C) 2002-2015 Bradley Spengler, Open Source Security, Inc.
 *        http://www.grsecurity.net spender@grsecurity.net
 *
 * This file is part of gradm.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include "gradm.h"

int bikeshedding_detected(void)
{
	struct stat64 st;

	if (!lstat64("/sbin", &st) && S_ISLNK(st.st_mode))
		return 1;
	return 0;
}

char *get_bikeshedded_path(const char *path)
{
	unsigned int len = strlen(path);
	struct stat64 st;
	char *buf = gr_alloc(len + strlen("/usr") + 1);

	if (strncmp(path, "/bin/", 5) && strncmp(path, "/sbin/", 6)) {
		strcpy(buf, path);
		return buf;
	}

	strcpy(buf, "/usr");

	/* lennart breaking things for the fun of it */
	if (!lstat64("/usr/sbin", &st) && S_ISLNK(st.st_mode) &&
	    !lstat64("/usr/bin", &st) && !S_ISLNK(st.st_mode) &&
	    !strncmp("/sbin/", path, 6)) {
		strcat(buf, "/bin/");
		strcat(buf, path + 6);
	} else
		strcat(buf, path);

	return buf;
}

char *get_anchor(const char *filename)
{
	char *basepoint = gr_strdup(filename);
	char *p, *p2;

	/* calculates basepoint, eg basepoint of /home/ * /test is /home */
	p = p2 = basepoint;
	while (*p != '\0') {
		if (*p == '/')
			p2 = p;
		if (*p == '?' || *p == '*' || *p == '[')
			break;
		p++;
	}
	/* if base is / */
	if (p2 == basepoint)
		*(p2 + 1) = '\0';
	else
		*p2 = '\0';

	return basepoint;
}

int anchorcmp(const char *path1, const char *path2)
{
	char *anchor1, *anchor2;
	int ret;

	anchor1 = get_anchor(path1);
	anchor2 = get_anchor(path2);
	ret = strcmp(anchor1, anchor2);
	free(anchor1);
	free(anchor2);
	return ret;
}

int is_globbed_file(const char *filename)
{
	if (strchr(filename, '*') || strchr(filename, '?') || strchr(filename, '['))
		return 1;
	else
		return 0;
}

int match_filename(const char *filename, const char *pattern, unsigned int len, int is_glob)
{
	if (is_glob)
		return fnmatch(pattern, filename, 0);
	else if (!strncmp(filename, pattern, len) &&
		   (filename[len] == '\0' || filename[len] == '/'))
		return 0;

	return 1;
}

void add_to_string_array(char *** array, const char *str)
{
	unsigned int size = 0;
	if (*array == NULL)
		*array = (char **)gr_alloc(2 * sizeof(char *));
	while (*(*array + size))
		size++;

	*array = (char **)gr_realloc(*array, (size + 2) * sizeof(char *));
	memset(*array + size, 0, 2 * sizeof(char *));
	// fix the warning for this
	*(const char **)(*array + size) = str;

	return;
}

char * gr_strdup(const char *p)
{
	char *ret;

	ret = strdup(p);
	if (ret == NULL)
		failure("strdup");
	return ret;
}

void * gr_alloc(size_t len)
{
	void *ptr;

	ptr = calloc(1, len);
	if (ptr == NULL)
		failure("calloc");

	return ptr;
}

void * gr_realloc(void *addr, size_t len)
{
	void *ptr;

	if (addr == NULL)
		return gr_alloc(len);

	ptr = realloc(addr, len);
	if (ptr == NULL)
		failure("realloc");

	return ptr;
}

void gr_free(void *addr)
{
	free(addr);

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
	return full_name_hash((const unsigned char *)name) % sz;
}

void insert_hash_entry(struct gr_hash_struct *hash, void *entry);
void insert_name_entry(struct gr_hash_struct *hash, void *entry);

void resize_hash_table(struct gr_hash_struct *hash)
{
	unsigned long i;
	struct gr_hash_struct *newhash;

	newhash = (struct gr_hash_struct *)gr_alloc(sizeof(struct gr_hash_struct));

	for (i = 0; i < sizeof(table_sizes)/sizeof(table_sizes[0]); i++) {
		if (table_sizes[i] > hash->table_size) {
			newhash->table_size = table_sizes[i];
			break;
		}
	}

	if (newhash->table_size == 0) {
		fprintf(stderr, "Out of memory.\n");
		exit(EXIT_FAILURE);
	}

	newhash->table = (void **)gr_alloc(newhash->table_size * sizeof(void *));
	newhash->nametable = NULL;
	if (hash->type != GR_HASH_FILENAME) {
		newhash->nametable = (void **)gr_alloc(newhash->table_size * sizeof(void *));
	}

	newhash->used_size = 0;
	newhash->type = hash->type;
	newhash->first = hash->first;

	for (i = 0; i < hash->table_size; i++)
		if (hash->table[i]) {
			insert_hash_entry(newhash, hash->table[i]);
			insert_name_entry(newhash, hash->table[i]);
		}

	free(hash->table);
	if (hash->nametable)
		free(hash->nametable);
	memcpy(hash, newhash, sizeof(struct gr_hash_struct));
	free(newhash);
	return;
}

void *lookup_name_entry(struct gr_hash_struct *hash, const char *name)
{
	if (hash == NULL)
		return NULL;
	if (hash->type == GR_HASH_OBJECT) {
		unsigned long index = nhash(name, hash->table_size);
		struct file_acl *match;
		unsigned char i = 0;

		match = (struct file_acl *)hash->nametable[index];

		while (match && strcmp(match->filename, name)) {
			index = (index + (1U << i)) % hash->table_size;
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
			index = (index + (1U << i)) % hash->table_size;
			match = (struct proc_acl *)hash->nametable[index];
			i = (i + 1) % 32;
		}

		return match;
	}
	return NULL;
}

struct file_acl *lookup_acl_object_by_name(struct proc_acl *subject, const char *name)
{
	return (struct file_acl *)lookup_name_entry(subject->hash, name);
}

struct proc_acl *lookup_acl_subject_by_name(struct role_acl *role, const char *name)
{
	return (struct proc_acl *)lookup_name_entry(role->hash, name);
}

void *lookup_hash_entry(struct gr_hash_struct *hash, const void *entry)
{
	if (hash == NULL)
		return NULL;

	if (hash->type == GR_HASH_OBJECT) {
		const struct file_acl *object = (const struct file_acl *)entry;
		unsigned long index = fhash(object->inode, object->dev, hash->table_size);
		struct file_acl *match;
		unsigned char i = 0;

		match = (struct file_acl *)hash->table[index];

		while (match && (match->inode != object->inode ||
		       match->dev != object->dev)) {
			index = (index + (1U << i)) % hash->table_size;
			match = (struct file_acl *)hash->table[index];
			i = (i + 1) % 32;
		}

		return match;
	} else if (hash->type == GR_HASH_SUBJECT) {
		const struct proc_acl *subject = (const struct proc_acl *)entry;
		unsigned long index = fhash(subject->inode, subject->dev, hash->table_size);
		struct proc_acl *match;
		unsigned char i = 0;

		match = (struct proc_acl *)hash->table[index];

		while (match && (match->inode != subject->inode ||
		       match->dev != subject->dev)) {
			index = (index + (1U << i)) % hash->table_size;
			match = (struct proc_acl *)hash->table[index];
			i = (i + 1) % 32;
		}

		return match;
	} else if (hash->type == GR_HASH_FILENAME) {
		const char *filename = (const char *)entry;
		u_int32_t key = full_name_hash((const unsigned char *)filename);
		u_int32_t index = key % hash->table_size;
		struct gr_learn_file_tmp_node *match;
		unsigned char i = 0;

		match = (struct gr_learn_file_tmp_node *)hash->table[index];

		while (match && (match->key != key || strcmp(match->filename, filename))) {
			index = (index + (1U << i)) % hash->table_size;
			match = (struct gr_learn_file_tmp_node *)hash->table[index];
			i = (i + 1) % 32;
		}

		return match;
	}
	return NULL;
}

static struct gr_hash_struct *mount_hash;

struct gr_learn_file_tmp_node *conv_filename_to_struct(const char *filename, u_int32_t mode)
{
	struct gr_learn_file_tmp_node *node;

	node = (struct gr_learn_file_tmp_node *)gr_alloc(sizeof(struct gr_learn_file_tmp_node));
	node->filename = gr_strdup(filename);
	node->mode = mode;

	return node;
}

void create_mount_hash(void)
{
	FILE *f = fopen("/proc/mounts", "r");
	char buf[4096] = { };
	char *p, *p2;
	struct gr_learn_file_tmp_node *node;

	mount_hash = create_hash_table(GR_HASH_FILENAME);

	if (f == NULL)
		return;

	while(fgets(buf, sizeof(buf)-1, f)) {
		p = strchr(buf, ' ');
		if (!p)
			continue;
		p2 = strchr(p+1, ' ');
		if (!p2)
			continue;
		*p2 = '\0';
		node = conv_filename_to_struct((const char *)p+1, 0);
		insert_hash_entry(mount_hash, node);
	}

	fclose(f);
}

int get_canonical_inodev(const char *name, u_int64_t *ino, u_int32_t *dev, int *is_symlink)
{
	struct stat64 st;
	char *dirname;
	char *parentdir;
	DIR *dir;
	struct dirent *dirent;

	if (is_symlink) {
		if (lstat64(name, &st))
			return 0;

		*is_symlink = S_ISLNK(st.st_mode);
	} else {
		if (stat64(name, &st))
			return 0;
	}

	*ino = st.st_ino;

	if (mount_hash == NULL)
		create_mount_hash();
	if (mount_hash == NULL || !lookup_hash_entry(mount_hash, name))
		goto normal;

	// if this is a mount root , obtain the inode of the mountpoint
	// instead so that we can hide mountpoints from readdir at least
	dirname = strrchr(name, '/');
	if (dirname == NULL)
		goto normal;
	parentdir = gr_alloc(strlen(name) + 4);

	/* skip past / */
	dirname++;

	strcpy(parentdir, name);
	strcat(parentdir, "/..");
	dir = opendir(parentdir);
	if (dir == NULL) {
		gr_free(parentdir);
		goto normal;
	}

	while ((dirent = readdir(dir))) {
		if (strcmp(dirent->d_name, dirname))
			continue;
		if (lstat64(parentdir, &st)) {
			closedir(dir);
			free(parentdir);
			goto normal;
		}
		*ino = dirent->d_ino;
		break;
	}
	closedir(dir);

normal:
	if (is_24_kernel)
		*dev = MKDEV_24(MAJOR_24(st.st_dev), MINOR_24(st.st_dev));
	else
		*dev = MKDEV_26(MAJOR_26(st.st_dev), MINOR_26(st.st_dev));

	return 1;
}

struct file_acl *lookup_acl_object_by_inodev(struct proc_acl *subject, const char *name)
{
	struct file_acl obj;

	if (!get_canonical_inodev(name, &obj.inode, &obj.dev, NULL))
		return NULL;

	return (struct file_acl *)lookup_hash_entry(subject->hash, (const void *)&obj);
}

struct file_acl *lookup_acl_object_by_inodev_nofollow(struct proc_acl *subject, const char *name)
{
	struct file_acl obj;
	int is_symlink;

	if (!get_canonical_inodev(name, &obj.inode, &obj.dev, &is_symlink))
		return NULL;

	return (struct file_acl *)lookup_hash_entry(subject->hash, (const void *)&obj);
}

struct file_acl *lookup_acl_object(struct proc_acl *subject, struct file_acl *object)
{
	struct file_acl *obj;
	obj = (struct file_acl *)lookup_hash_entry(subject->hash, (const struct file_acl *)object);
	if (obj && !(obj->mode & GR_DELETED) && !(object->mode & GR_DELETED))
		return obj;
	else
		return NULL;
}

struct gr_learn_file_tmp_node *lookup_learn_object(struct gr_learn_file_node *subject, char *filename)
{
	return (struct gr_learn_file_tmp_node *)lookup_hash_entry(subject->hash, (const char *)filename);
}

struct gr_learn_file_tmp_node *lookup_learn_role_subject(struct gr_learn_role_entry *role, char *filename)
{
	return (struct gr_learn_file_tmp_node *)lookup_hash_entry(role->hash, (const char *)filename);
}

struct gr_learn_file_tmp_node *lookup_learn_group_subject(struct gr_learn_group_node *role, char *filename)
{
	return (struct gr_learn_file_tmp_node *)lookup_hash_entry(role->hash, (const char *)filename);
}

struct gr_learn_file_tmp_node *lookup_learn_user_subject(struct gr_learn_user_node *role, char *filename)
{
	return (struct gr_learn_file_tmp_node *)lookup_hash_entry(role->hash, (const char *)filename);
}

struct proc_acl *lookup_acl_subject(struct role_acl *role, struct proc_acl *subject)
{
	return (struct proc_acl *)lookup_hash_entry(role->hash, (const struct proc_acl *)subject);
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
			index = (index + (1U << i)) % hash->table_size;
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
			index = (index + (1U << i)) % hash->table_size;
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
			index = (index + (1U << i)) % hash->table_size;
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
			index = (index + (1U << i)) % hash->table_size;
			curr = (struct proc_acl **)&hash->table[index];
			i = (i + 1) % 32;
		}

		*curr = (struct proc_acl *)entry;
		insert_name_entry(hash, *curr);
		hash->used_size++;
	} else if (hash->type == GR_HASH_FILENAME) {
		struct gr_learn_file_tmp_node *node = (struct gr_learn_file_tmp_node *)entry;
		u_int32_t key = full_name_hash((unsigned char *)node->filename);
		u_int32_t index = key % hash->table_size;
		struct gr_learn_file_tmp_node **curr;
		unsigned char i = 0;

		curr = (struct gr_learn_file_tmp_node **)&hash->table[index];

		while (*curr && ((*curr)->key != key || strcmp(node->filename, (*curr)->filename))) {
			index = (index + (1U << i)) % hash->table_size;
			curr = (struct gr_learn_file_tmp_node **)&hash->table[index];
			i = (i + 1) % 32;
		}

		if (*curr) {
			(*curr)->mode |= node->mode;
			free(node->filename);
			gr_free(node);
		} else {
			*curr = (struct gr_learn_file_tmp_node *)entry;
			(*curr)->key = key;
			hash->used_size++;
		}
	}
}

struct gr_hash_struct *create_hash_table(int type)
{
	struct gr_hash_struct *hash;

	hash = (struct gr_hash_struct *)gr_alloc(sizeof(struct gr_hash_struct));
	hash->table = (void **)gr_alloc(table_sizes[0] * sizeof(void *));
	if (type != GR_HASH_FILENAME) {
		hash->nametable = (void **)gr_alloc(table_sizes[0] * sizeof(void *));
	}
	hash->table_size = table_sizes[0];
	hash->type = type;

	return hash;
}

void insert_learn_object(struct gr_learn_file_node *subject, struct gr_learn_file_tmp_node *object)
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
		object->prev = (struct file_acl *)subject->hash->first;
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
		subject->prev = (struct proc_acl *)role->hash->first;
		role->hash->first = subject;
	}
	/* force every subject to have a hash table whether or not they
	   have any objects */
	subject->hash = create_hash_table(GR_HASH_OBJECT);
	insert_hash_entry(role->hash, subject);

	return;
}

void insert_nested_acl_subject(struct proc_acl *subject)
{
	/* we won't iterate over these subjects via for_each_subject, so add them to a special list */
	if (global_nested_subject_list == NULL) {
		global_nested_subject_list = subject;
		subject->next = NULL;
	} else {
		subject->next = global_nested_subject_list;
		global_nested_subject_list = subject;
	}

	/* force every subject to have a hash table whether or not they
	   have any objects */
	subject->hash = create_hash_table(GR_HASH_OBJECT);
	return;
}

struct gr_user_map {
	uid_t uid;
	char *user;
	struct gr_user_map *next;
};

struct gr_group_map {
	gid_t gid;
	char *group;
	struct gr_group_map *next;
};

static struct gr_user_map *user_list;
static struct gr_group_map *group_list;

const char *gr_get_user_name(uid_t uid)
{
	struct gr_user_map *tmpuser = user_list;
	struct passwd *pwd;

	for_each_list_entry(tmpuser, user_list) {
		if (tmpuser->uid == uid)
			return tmpuser->user;
	}

	pwd = getpwuid(uid);

	if (pwd) {
		tmpuser = (struct gr_user_map *)gr_alloc(sizeof(struct gr_user_map));
		tmpuser->uid = uid;
		tmpuser->user = gr_strdup(pwd->pw_name);
		tmpuser->next = user_list;
		user_list = tmpuser;
		return pwd->pw_name;
	} else
		return NULL;
}

const char *gr_get_group_name(gid_t gid)
{
	struct gr_group_map *tmpgroup;
	struct group *grp;

	for_each_list_entry (tmpgroup, group_list) {
		if (tmpgroup->gid == gid)
			return tmpgroup->group;
	}

	grp = getgrgid(gid);

	if (grp) {
		tmpgroup = (struct gr_group_map *)gr_alloc(sizeof(struct gr_group_map));
		tmpgroup->gid = gid;
		tmpgroup->group = gr_strdup(grp->gr_name);
		tmpgroup->next = group_list;
		group_list = tmpgroup;
		return grp->gr_name;
	} else
		return NULL;
}

