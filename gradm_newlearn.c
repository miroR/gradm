#include "gradm.h"

char *high_reduce_dirs[] = {
				"/tmp",
				"/var/tmp",
				"/proc",
				"/lib",
				"/lib/security",
				"/lib/modules",
				"/usr/lib",
				"/var/lib",
				"/usr/bin",
				"/usr/sbin",
				"/sbin",
				"/etc",
				"/bin",
				"/usr/local/share",
				"/usr/local/bin",
				"/usr/local/sbin",
				"/usr/local/etc",
				"/usr/local/lib",
				"/usr/share",
				"/usr/share/locale",
				"/usr/share/zoneinfo",
				"/usr/X11R6/lib",
				NULL
			   };

char *dont_reduce_dirs[] = {
				"/",
				"/dev",
				NULL
			   };

char *protected_paths[] = {
				"/etc",
				"/lib",
				"/boot",
				"/usr/lib",
				"/usr/local",
				"/opt",
				"/var",
				"/dev/log",
				"/root",
				NULL
			};

char *high_protected_paths[] = {
				"/etc/ssh",
				GRSEC_DIR,
				"/dev/grsec",
				"/proc/kcore",
				"/proc/sys",
				"/etc/shadow",
				"/etc/passwd",
				"/var/log",
				"/dev/mem",
				"/dev/kmem",
				"/dev/port",
				"/dev/log",
				NULL
			};

int is_protected_path(char *filename, __u32 mode)
{
	char **tmp;
	unsigned int len;

	if (!(mode & (GR_WRITE | GR_APPEND)))
		return 0;

	tmp = protected_paths;
	while (*tmp) {
		len = strlen(*tmp);
		if (!strncmp(filename, *tmp, len) &&
		    (filename[len] == '\0' || filename[len] == '/'))
			return 1;
		tmp++;
	}

	return 0;
}

void enforce_high_protected_paths(struct gr_learn_file_node *subject)
{
	struct gr_learn_file_tmp_node **tmpfile;
	char **tmp;
	unsigned int len;

	tmp = high_protected_paths;
	while (*tmp) {
		len = strlen(*tmp);
		tmpfile = subject->tmp_object_list;
		while (tmpfile && *tmpfile) {
			if (!(*tmpfile)->mode) {
				tmpfile++;
				continue;
			}
			if (!strncmp((*tmpfile)->filename, *tmp, len) &&
			    ((*tmpfile)->filename[len] == '\0' || (*tmpfile)->filename[len] == '/'))
				goto next;
			tmpfile++;
		}
		insert_file(&(subject->object_list), *tmp, 0, 0);
next:
		tmp++;
	}
			
	return;
}

void match_role(struct gr_learn_group_node **grouplist, uid_t uid, gid_t gid, struct gr_learn_group_node **group,
		struct gr_learn_user_node **user)
{
	struct gr_learn_group_node **tmpgroup;
	struct gr_learn_user_node **tmpuser;

	*group = NULL;
	*user = NULL;

	tmpgroup = grouplist;

	if (!tmpgroup)
		return;

	while (*tmpgroup) {
		tmpuser = (*tmpgroup)->users;
		while (tmpuser && *tmpuser) {
			if ((*tmpuser)->uid == uid) {
				*user = *tmpuser;
				return;
			}
			tmpuser++;
		}
		tmpgroup++;
	}

	tmpgroup = grouplist;

	while (*tmpgroup) {
		if ((*tmpgroup)->gid == gid) {
			*group = *tmpgroup;
			return;
		}
		tmpgroup++;
	}
				
	return;
}

void traverse_roles(struct gr_learn_group_node **grouplist, 
		    int (*act)(struct gr_learn_group_node *group, struct gr_learn_user_node *user, FILE *stream),
		    FILE *stream)
{
	struct gr_learn_group_node **tmpgroup;
	struct gr_learn_user_node **tmpuser;

	tmpgroup = grouplist;

	if (!tmpgroup)
		return;

	while(*tmpgroup) {
		tmpuser = (*tmpgroup)->users;
		if (!tmpuser)
			act(*tmpgroup, NULL, stream);
		else {
			while(*tmpuser) {
				act(*tmpgroup, *tmpuser, stream);
				tmpuser++;
			}
		}
		tmpgroup++;
	}

	return;
}

int display_role(struct gr_learn_group_node *group, struct gr_learn_user_node *user, FILE *stream)
{
	struct gr_learn_file_node *subject = NULL;
	struct gr_learn_ip_node *allowed_ips = NULL;

	if (user) {
		fprintf(stream, "role %s u%s\n", user->rolename, strcmp(user->rolename, "root") ? "" : "G");
		subject = user->subject_list;
		allowed_ips = user->allowed_ips;
	} else {
		fprintf(stream, "role %s g\n", group->rolename);
		subject = group->subject_list;
		allowed_ips = group->allowed_ips;
	}

	if (allowed_ips)
		traverse_ip_tree(allowed_ips, NULL, &display_only_ip, 0, stream);

	if (subject)
		display_tree(subject, stream);

	fprintf(stream, "\n");

	return 0;
}

void display_roles(struct gr_learn_group_node **grouplist, FILE *stream)
{
	fprintf(stream, "role default\n");
	fprintf(stream, "   subject / {\n");
	fprintf(stream, "      /                                                  h\n");
	fprintf(stream, "      -CAP_ALL\n");
	fprintf(stream, "      connect\tdisabled\n");
	fprintf(stream, "      bind\tdisabled\n");
	fprintf(stream, "   }\n\n");
	traverse_roles(grouplist, &display_role, stream);
	return;
}
	
struct gr_learn_group_node **find_insert_group(struct gr_learn_group_node ***grouplist, gid_t gid)
{
	struct gr_learn_group_node **tmp = *grouplist;
	unsigned long num = 0;

	if (!tmp) {
		*grouplist = calloc(2, sizeof(struct gr_learn_group_node *));
		if (!(*grouplist))
			failure("calloc");
		return (*grouplist);
	}

	while(*tmp) {
		if ((*tmp)->gid == gid)
			return tmp;
		tmp++;
		num++;
	}

	*grouplist = realloc(*grouplist, (num + 2) * sizeof(struct gr_learn_group_node *));
	if (!(*grouplist))
		failure("realloc");
	memset(*grouplist + num, 0, 2 * sizeof(struct gr_learn_group_node *));
 
	return (*grouplist + num);
}

unsigned long count_users(struct gr_learn_group_node *group)
{
	struct gr_learn_user_node **tmp;
	unsigned long ret = 0;

	tmp = group->users;

	if (!tmp)
		return 0;

	while (*tmp) {
		ret++;
		tmp++;
	}

	return ret;
}

void insert_user(struct gr_learn_group_node ***grouplist, char *username, char *groupname, uid_t uid, gid_t gid)
{
	struct gr_learn_group_node **group;
	struct gr_learn_user_node **tmpuser;
	struct gr_learn_user_node **tmp;
	unsigned long num;

	/* first check to see if the user exists in any group */

	group = *grouplist;
	while (group && *group) {
		tmpuser = (*group)->users;
		while (tmpuser && *tmpuser) {
			if ((*tmpuser)->uid == uid)
				return;
			tmpuser++;
		}
		group++;
	}

	group = find_insert_group(grouplist, gid);

	if (*group) {
		tmp = (*group)->users;
		while (tmp && *tmp) {
			if ((*tmp)->uid == uid)
				return;
			tmp++;
		}
		num = count_users(*group);

		(*group)->users = realloc((*group)->users, (num + 2) * sizeof(struct gr_learn_user_node *));
		if (!((*group)->users))
			failure("realloc");

		memset((*group)->users + num, 0, 2 * sizeof(struct gr_learn_user_node *));

		tmpuser = ((*group)->users + num);
		*tmpuser = calloc(1, sizeof(struct gr_learn_user_node));
		if (!(*tmpuser))
			failure("calloc");
		(*tmpuser)->rolename = username;
		(*tmpuser)->uid = uid;
		(*tmpuser)->group = *group;
	} else {
		*group = calloc(1, sizeof(struct gr_learn_group_node));
		if (!(*group))
			failure("calloc");
		(*group)->rolename = groupname;
		(*group)->gid = gid;
		(*group)->users = calloc(2, sizeof(struct gr_learn_user_node *));
		if (!((*group)->users))
			failure("calloc");
		tmpuser = (*group)->users;
		*tmpuser = calloc(1, sizeof(struct gr_learn_user_node));
		if (!(*tmpuser))
			failure("calloc");
		(*tmpuser)->rolename = username;
		(*tmpuser)->uid = uid;
		(*tmpuser)->group = *group;
	}

	return;
}

void reduce_roles(struct gr_learn_group_node ***grouplist)
{
	unsigned int thresh = 3;
	struct gr_learn_group_node **group = *grouplist;
	struct gr_learn_user_node **tmpuser;
	unsigned long num;

	while (group && *group) {
		num = count_users(*group);
		if (num >= thresh) {
			tmpuser = (*group)->users;
			while(*tmpuser) {
				free(*tmpuser);
				*tmpuser = NULL;
				tmpuser++;
			}
			free((*group)->users);
			(*group)->users = NULL;
		}
		group++;
	}
	
	return;
}

void traverse_file_tree(struct gr_learn_file_node *base,
		   int (*act)(struct gr_learn_file_node *node, struct gr_learn_file_node *optarg, FILE *stream),
		   struct gr_learn_file_node *optarg, FILE *stream)
{
	struct gr_learn_file_node **node;

	if (!base)
		return;

	act(base, optarg, stream);

	node = base->leaves;

	if (!node)
		return;

	while(*node) {
		traverse_file_tree(*node, act, optarg, stream);
		node++;
	}

	return;
}

struct gr_learn_file_node *match_file_node(struct gr_learn_file_node *base,
					const char *filename)
{
	struct gr_learn_file_node **node, *ret;
	unsigned int baselen, filelen;

	filelen = strlen(filename);

	if (!base)
		return base;

	baselen = strlen(base->filename);
	if ((filelen == baselen) && !strcmp(base->filename, filename))
		return base;

	if ((baselen >= filelen) || strncmp(base->filename, filename, baselen) || (filename[baselen] != '/' && baselen != 1))
		return NULL;

	node = base->leaves;

	if (!node)
		return base;

	while(*node) {
		if ((ret = match_file_node(*node, filename)))
			return ret;
		node++;
	}
	
	return base;
}

unsigned long count_nodes(struct gr_learn_file_node **node)
{
	unsigned long ret = 0;

	if (!node)
		return 0;

	while(*node) {
		ret++;
		node++;
	}

	return ret;
}

unsigned long count_leaf_nodes(struct gr_learn_file_node **node)
{
	unsigned long ret = 0;

	if (!node)
		return 0;

	while(*node) {
		if (!((*node)->leaves))
			ret++;
		node++;
	}

	return ret;
}

unsigned long count_total_leaves(struct gr_learn_file_node *node)
{
	unsigned long leaves = 0;
	struct gr_learn_file_node **tmp;

	tmp = node->leaves;
	if (!tmp)
		return 0;

	while(*tmp) {
		leaves++;
		leaves += count_total_leaves(*tmp);
		tmp++;
	}

	return leaves;
}

unsigned long count_max_depth(struct gr_learn_file_node *node)
{
	unsigned long max = 0, tmpmax = 0;
	struct gr_learn_file_node **tmp;

	tmp = node->leaves;
	if (!tmp)
		return 0;

	max++;
	while(*tmp) {
		tmpmax = count_max_depth(*tmp);
		if ((max + tmpmax) > max)
			max = tmpmax + max;
		tmp++;
	}

	return max;
}	

unsigned long count_nested_depth(struct gr_learn_file_node *node)
{
	unsigned long depth = 0;
	struct gr_learn_file_node *tmp;

	tmp = node->parent;
	if (!tmp)
		return 0;

	while(tmp) {
		depth++;
		tmp = tmp->parent;
	}

	return depth;
}	

int reduce_all_children(struct gr_learn_file_node *node)
{
	unsigned long num, not_leaf = 0;
	unsigned long i, j;
	struct gr_learn_file_node **tmp;
	
	tmp = node->leaves;
	num = 0;
	while (*tmp) {
		if (!((*tmp)->leaves)) {
			node->mode |= (*tmp)->mode;
			if (node->subject && (*tmp)->subject) {
				node->subject->cap_raise |= (*tmp)->subject->cap_raise;
				node->subject->resmask |= (*tmp)->subject->resmask;
				for (i = 0; i < GR_NLIMITS; i++) {
					if ((*tmp)->subject->res[i].rlim_cur > node->subject->res[i].rlim_cur)
						node->subject->res[i].rlim_cur = (*tmp)->subject->res[i].rlim_cur;
					if ((*tmp)->subject->res[i].rlim_max > node->subject->res[i].rlim_max)
						node->subject->res[i].rlim_max = (*tmp)->subject->res[i].rlim_max;
				}
			}
		} else
			not_leaf++;
		tmp++;
		num++;
	}

	tmp = node->leaves;
	for (i = 0; i < num; i++) {
		if (*(tmp + i) && !(*(tmp + i))->leaves) {
			free(*(tmp + i));
			*(tmp + i) = NULL;
			j = i;
			while (*(tmp + j + 1)) {
				*(tmp + j) = *(tmp + j + 1);
				j++;
			}
			*(tmp + j) = NULL;			
		}
	}

	if (!not_leaf) {
		free(node->leaves);
		node->leaves = NULL;
		return 0;
	}

	return 0;
}

int reduce_all_leaves(struct gr_learn_file_node *node)
{
	struct gr_learn_file_node **tmp;
	unsigned int i;

	tmp = node->leaves;
	if (!tmp)
		return 0;
	while (*tmp) {
		reduce_all_leaves(*tmp);
		node->mode |= (*tmp)->mode;
		if (node->subject && (*tmp)->subject) {
			node->subject->cap_raise |= (*tmp)->subject->cap_raise;
			node->subject->resmask |= (*tmp)->subject->resmask;
			for (i = 0; i < GR_NLIMITS; i++) {
				if ((*tmp)->subject->res[i].rlim_cur > node->subject->res[i].rlim_cur)
					node->subject->res[i].rlim_cur = (*tmp)->subject->res[i].rlim_cur;
				if ((*tmp)->subject->res[i].rlim_max > node->subject->res[i].rlim_max)
					node->subject->res[i].rlim_max = (*tmp)->subject->res[i].rlim_max;
			}
		}
		free(*tmp);
		*tmp = NULL;
		tmp++;
	}
	free(node->leaves);
	node->leaves = NULL;

	return 0;
}

int analyze_node_read_permissions(struct gr_learn_file_node *node)
{
	struct gr_learn_file_node **tmp;

	if (!node->leaves)
		return 1;

	tmp = node->leaves;

	while (*tmp) {
		if (((*tmp)->mode & GR_WRITE) && !((*tmp)->mode & GR_READ))
			return 0;
		if (!analyze_node_read_permissions(*tmp))
			return 0;
		tmp++;
	}

	return 1;
}

int analyze_node_write_permissions(struct gr_learn_file_node *node)
{
	struct gr_learn_file_node **tmp;

	if (!node->leaves)
		return 1;

	tmp = node->leaves;

	while (*tmp) {
		if (!((*tmp)->mode & GR_WRITE) && ((*tmp)->mode & GR_READ))
			return 0;
		if (!analyze_node_write_permissions(*tmp))
			return 0;
		tmp++;
	}

	return 1;
}

int analyze_child_read_permissions(struct gr_learn_file_node *node)
{
	struct gr_learn_file_node **tmp;

	if (!node->leaves)
		return 1;

	tmp = node->leaves;

	while (*tmp) {
		if ((*tmp)->leaves) {
			tmp++;
			continue;
		}
		if (((*tmp)->mode & GR_WRITE) && !((*tmp)->mode & GR_READ))
			return 0;
		tmp++;
	}

	return 1;
}

int analyze_child_write_permissions(struct gr_learn_file_node *node)
{
	struct gr_learn_file_node **tmp;

	if (!node->leaves)
		return 1;

	tmp = node->leaves;

	while (*tmp) {
		if ((*tmp)->leaves) {
			tmp++;
			continue;
		}
		if (!((*tmp)->mode & GR_WRITE) && ((*tmp)->mode & GR_READ))
			return 0;
		tmp++;
	}

	return 1;
}

int *analyze_node_reduction(struct gr_learn_file_node *node)
{
	int reduce_child_thresh = 4;
	int reduce_leaves_thresh = 8;
	int reduction_level = 0;
	unsigned long node_num;
	unsigned long child_num;
	unsigned long depth_num;
	unsigned long nested_num;
	char **tmp;

	if (!node->leaves)
		return NULL;

	node_num = count_leaf_nodes(node->leaves);
	child_num = count_total_leaves(node);
	depth_num = count_max_depth(node);
	nested_num = count_nested_depth(node);

	tmp = dont_reduce_dirs;
	while (*tmp) {
		if (!strcmp(node->filename, *tmp))
			return NULL;
		tmp++;
	}

	if (node_num > 3)
		reduction_level++;
	if (node_num > 6)
		reduction_level++;
	if (node_num > 20)
		reduction_level++;
	if (nested_num > 2)
		reduction_level++;
	if (nested_num > 4)
		reduction_level++;
	if (nested_num > 6)
		reduction_level++;
	if (child_num > 5)
		reduction_level++;
	if (child_num > 10)
		reduction_level++;
	if (child_num > 20)
		reduction_level++;
	if (child_num > 40)
		reduction_level++;
	if (child_num > 80)
		reduction_level++;
	if (depth_num > 2)
		reduction_level++;
	if (depth_num > 4)
		reduction_level++;
	if (depth_num > 6)
		reduction_level++;

	if (analyze_node_read_permissions(node) || analyze_node_write_permissions(node))
		reduction_level *= 2;
	else {
		if (analyze_child_read_permissions(node) || analyze_child_write_permissions(node))
			reduction_level = reduce_child_thresh;
		else {
			if (nested_num < 3)
				reduction_level /= 8;
			if (reduction_level > 8)
				reduction_level /= 4;
			if (depth_num > 5)
				reduction_level /= 2;
		}
	}

	tmp = high_reduce_dirs;
	while (*tmp) {
		if (!strcmp(node->filename, *tmp) && ((node_num > 4) || (child_num > 10)))
			reduction_level *= 2;
		tmp++;
	}

	if (reduction_level >= reduce_leaves_thresh)
		return (int *)&reduce_all_leaves;
	else if (reduction_level >= reduce_child_thresh)
		return (int *)&reduce_all_children;
	else
		return NULL;
}

int second_reduce_node(struct gr_learn_file_node *node,
		       struct gr_learn_file_node *unused1, FILE *unused)
{
	int (* retval)(struct gr_learn_file_node *node);

	retval = (int (*)(struct gr_learn_file_node *))analyze_node_reduction(node);

	if (retval)
		retval(node);

	return 0;
}		

void second_stage_reduce_tree(struct gr_learn_file_node *base)
{
	return traverse_file_tree(base, &second_reduce_node, NULL, NULL);
}

int third_reduce_node(struct gr_learn_file_node *node,
		       struct gr_learn_file_node *unused1, FILE *unused)
{
	struct gr_learn_file_node **tmp, **tmp2;

	tmp = node->leaves;

	if (!tmp)
		return 0;

	while (*tmp) {
		if ((*tmp)->leaves) {
			tmp++;
			continue;
		}
		if ((*tmp)->mode == node->mode ||
		    (((node->mode & (GR_WRITE | GR_CREATE)) == (GR_WRITE | GR_CREATE)) &&
		    ((*tmp)->mode & GR_WRITE))) {
			node->mode |= (*tmp)->mode;
			tmp2 = tmp;
			free(*tmp);
			*tmp = NULL;
			while(*(tmp2 + 1)) {
				*tmp2 = *(tmp2 + 1);
				tmp2++;
			}
			*tmp2 = NULL;
		} else
			tmp++;
	}

	return 0;
}	
		

void third_stage_reduce_tree(struct gr_learn_file_node *base)
{
	return traverse_file_tree(base, &third_reduce_node, NULL, NULL);
}

struct gr_learn_file_node **find_insert_file(struct gr_learn_file_node **base,
					struct gr_learn_file_node *insert, unsigned int filelen,
					struct gr_learn_file_node **parent)
{
	struct gr_learn_file_node **node, **tmpnode, **ret;
	unsigned int baselen;
	unsigned long num_leaves;

	if (!*base) {
		*parent = *base;
		return base;
	}

	baselen = strlen((*base)->filename);
	if ((filelen == baselen) && !strcmp((*base)->filename, insert->filename))
		return base;

	node = (*base)->leaves;

	if (!node && (baselen < filelen) && !strncmp((*base)->filename, insert->filename, baselen) && 
	    (baselen == 1 || insert->filename[baselen] == '/')) {
		*parent = *base;
		(*base)->leaves = node = calloc(2, sizeof(struct gr_learn_file_node *));
		if (!node)
			failure("calloc");
		return node;
	} else if (!node)
		return NULL;

	tmpnode = node;

	while(*tmpnode) {
		ret = find_insert_file(tmpnode, insert, filelen, parent);
		if (ret)
			return ret;
		tmpnode++;
	}
	
	if ((baselen >= filelen) || strncmp((*base)->filename, insert->filename, baselen) || 
	    (baselen != 1 && insert->filename[baselen] != '/'))
		return NULL;

	*parent = *base;
	num_leaves = count_nodes(node);
	(*base)->leaves = node = realloc((*base)->leaves, (num_leaves + 2) * sizeof(struct gr_learn_file_node *));
	if (!node)
		failure("realloc");

	memset(node + num_leaves, 0, 2 * sizeof(struct gr_learn_file_node *));
	return (node + num_leaves);
}



void do_insert_file(struct gr_learn_file_node **base, char *filename, __u32 mode, __u8 subj)
{
	struct gr_learn_file_node **node;
	struct gr_learn_file_node *parent = NULL;
	struct gr_learn_file_node *insert;

	insert = calloc(1, sizeof(struct gr_learn_file_node));
	if (!insert)
		failure("calloc");

	insert->filename = filename;
	insert->mode = mode;
	if (subj)
		insert_file(&(insert->object_list), strdup("/"), 0, 0);		

	node = find_insert_file(base, insert, strlen(filename), &parent);

	if (*node) {
		(*node)->mode |= mode;
		(*node)->dont_display = 0;
		free(insert);
		return;
	} else {
		*node = insert;
		(*node)->parent = parent;
	}

	return;
}

void insert_file(struct gr_learn_file_node **base, char *filename, __u32 mode, __u8 subj)
{
	/* we're inserting a new file, and an entry for / does not exist, add it */
	if (!(*base)) {
		if (subj) {
			do_insert_file(base, strdup("/"), GR_FIND, subj);
			if (subj == 2) /* learning in non-full mode, don't display / subject */
				(*base)->dont_display = 1;
		} else
			do_insert_file(base, strdup("/"), 0, subj);
	}

	do_insert_file(base, filename, mode, subj);

	return;
}

int first_reduce_node(struct gr_learn_file_node *node,
		       struct gr_learn_file_node *unused1, FILE *unused)
{
	unsigned long thresh = 5;	
	unsigned long cnt = 0;
	unsigned long num = count_nodes(node->leaves);
	struct gr_learn_file_node **tmp, **tmp2, **tmp3, *tmp4;
	struct gr_learn_file_node *parent = NULL;
	char *p, *p2;
	unsigned int node_len = strlen(node->filename);

	if (num < thresh)
		return 0;

	tmp = node->leaves;

	while (*tmp) {
		p = strdup((*tmp)->filename);
		if (node_len == 1)
			p2 = strchr(p + 1, '/');
		else
			p2 = strchr(p + node_len + 1, '/');

		if (!p2) {
			tmp++;
			cnt++;
			continue;
		}

		*p2 = '\0';
		insert_file(&node, p, 0, 0);
		cnt++;
		/* node->leaves might have been modified during insert */
		tmp = node->leaves + cnt;
	}

	tmp = node->leaves;

	while (*tmp && num) {
		parent = NULL;
		tmp4 = *tmp;
		tmp2 = tmp;
		while(*(tmp2 + 1)) {
			*tmp2 = *(tmp2 + 1);
			tmp2++;
		}
		*tmp2 = NULL;
		tmp3 = find_insert_file(&node, tmp4, strlen(tmp4->filename), &parent);
		if (!(*tmp3)) {
			*tmp3 = tmp4;
			(*tmp3)->parent = parent;
		}
		num--;
	}

	return 0;
}

void first_stage_reduce_tree(struct gr_learn_file_node *base)
{
	return traverse_file_tree(base, &first_reduce_node, NULL, NULL);
}

int display_leaf(struct gr_learn_file_node *node,
		       struct gr_learn_file_node *unused1, FILE *stream);

void display_tree(struct gr_learn_file_node *base, FILE *stream)
{
	traverse_file_tree(base, &display_leaf, NULL, stream);
	return;
}

int display_leaf(struct gr_learn_file_node *node,
		       struct gr_learn_file_node *unused1, FILE *stream)
{
	char modes[33];
	int i;

	if (node->dont_display)
		return 0;

	if (node->object_list) {
		struct gr_learn_file_node *object;
		struct gr_learn_ip_node *connect;
		struct gr_learn_ip_node *bind;
		unsigned int raise_num;

		object = node->object_list;
		connect = node->connect_list;
		bind = node->bind_list;
		conv_subj_mode_to_str(node->mode, modes, sizeof(modes));
		fprintf(stream, "   subject %s %s {\n", node->filename, modes);
		if (object)
			display_tree(object, stream);
		if (!node->subject) {
			fprintf(stream, "      -CAP_ALL\n");
			goto show_ips;
		}

		for(i = raise_num = 0; i < ((sizeof(capability_list)/sizeof(struct capability_set)) - 1); i++)
			if (node->subject->cap_raise & (1 << capability_list[i].cap_val))
				raise_num++;

		if (raise_num < ((sizeof(capability_list)/sizeof(struct capability_set)) - 1) / 2) {
			fprintf(stream, "      -CAP_ALL\n");
			for(i = 0; i < ((sizeof(capability_list)/sizeof(struct capability_set)) - 1); i++)
				if (node->subject->cap_raise & (1 << capability_list[i].cap_val))
					fprintf(stream, "      +%s\n", capability_list[i].cap_name);
		} else {
			fprintf(stream, "      +CAP_ALL\n");
			for(i = 0; i < ((sizeof(capability_list)/sizeof(struct capability_set)) - 1); i++)
				if (!(node->subject->cap_raise & (1 << capability_list[i].cap_val)))
					fprintf(stream, "      -%s\n", capability_list[i].cap_name);
		}

		for(i = 0; i < (sizeof(rlim_table)/sizeof(struct rlimconv)); i++)
			if (node->subject->resmask & (1 << rlim_table[i].val))
				fprintf(stream, "      %s %lu %lu\n",
					rlim_table[i].name,
					node->subject->res[i].rlim_cur,
					node->subject->res[i].rlim_max);

show_ips:
		if (bind)
			display_ip_tree(bind, GR_IP_BIND, stream);
		else
			fprintf(stream, "      bind\tdisabled\n");
		if (connect)
			display_ip_tree(connect, GR_IP_CONNECT, stream);
		else
			fprintf(stream, "      connect\tdisabled\n");

		fprintf(stream, "   }\n\n");
	} else {
		conv_mode_to_str(node->mode, modes, sizeof(modes));
		i = strlen(node->filename);
		if (strchr(node->filename, ' ')) {
				fprintf(stream, "      \"%s\"\t%s\n", node->filename, modes);
		} else {
			if (i < 50)
				fprintf(stream, "      %-50s %s\n", node->filename, modes);
			else
				fprintf(stream, "      %s\t%s\n", node->filename, modes);
		}
	}
	return 0;
}

void traverse_ip_tree(struct gr_learn_ip_node *base,
		   struct gr_learn_ip_node **optarg,
		   int (*act)(struct gr_learn_ip_node *node, struct gr_learn_ip_node **optarg, __u8 contype, FILE *stream),
		   __u8 contype, FILE *stream)
{
	struct gr_learn_ip_node **node;

	if (!base)
		return;

	act(base, optarg, contype, stream);
	
	node = base->leaves;

	while(node && *node) {
		traverse_ip_tree(*node, optarg, act, contype, stream);
		node++;
	}

	return;
}

int count_ip_depth(struct gr_learn_ip_node *node)
{
	int depth = 0;

	while ((node = node->parent))
		depth++;

	return depth;
}

unsigned long count_total_ips(struct gr_learn_ip_node *node)
{
	unsigned long ips = 0;
	struct gr_learn_ip_node **tmp;

	tmp = node->leaves;
	if (!tmp)
		return 1;

	while(*tmp) {
		ips += count_total_ips(*tmp);
		tmp++;
	}

	return ips;
}
	

int display_ip_node(struct gr_learn_ip_node *node, struct gr_learn_ip_node **unused, __u8 contype,
		    FILE *stream)
{
	struct gr_learn_ip_node *saved = node;
	int depth = count_ip_depth(node);
	__u16 **tmpport;
	__u8 ip[4];
	char ipandtype[64] = {0};
	char socktypeandprotos[4096] = {0};
	struct protoent *proto;
	int netmask = 0;
	int i;

	if (node->leaves)
		return 0;

	if (!node->root_node)
		netmask = 8 * depth;
	else {
		ip[0] = ip[1] = ip[2] = ip[3] = 0;
		goto print_ip;
	}

	for(i = 3; i >= 0; i--) {
		if (depth < (i + 1))
			ip[i] = 0;
		else {
			ip[i] = node->ip_node;
			node = node->parent;
		}
	}

print_ip:
	node = saved;
	if (contype == GR_IP_CONNECT)
		sprintf(ipandtype, "      connect %u.%u.%u.%u/%u", ip[0], ip[1], ip[2], ip[3], netmask);
	else if (contype == GR_IP_BIND)
		sprintf(ipandtype, "      bind %u.%u.%u.%u/%u", ip[0], ip[1], ip[2], ip[3], netmask);

	for (i = 1; i < 5; i++) {
		if (node->ip_type & (1 << i)) {
			switch (i) {
			case SOCK_RAW:
				strcat(socktypeandprotos, " raw_sock");
				break;
			case SOCK_DGRAM:
				strcat(socktypeandprotos, " dgram");
				break;
			case SOCK_STREAM:
				strcat(socktypeandprotos, " stream");
				break;
			case SOCK_RDM:
				strcat(socktypeandprotos, " rdm");
				break;
			}
		}
	}

	for (i = 0; i < 256; i++) {
		if (node->ip_proto[i / 32] & (1 << (i % 32))) {
			if (i == IPPROTO_RAW) {
				strcat(socktypeandprotos, " raw_proto");
			} else {
				proto = getprotobynumber(i);
				strcat(socktypeandprotos, " ");
				strcat(socktypeandprotos, proto->p_name);
			}
		}
	}

	if (node->all_low_ports && node->all_high_ports)
		fprintf(stream, "%s:0-65535%s\n", ipandtype, socktypeandprotos);
	else if (node->all_low_ports)
		fprintf(stream, "%s:0-1023%s\n", ipandtype, socktypeandprotos);
	else if (node->all_high_ports)
		fprintf(stream, "%s:1024-65535%s\n", ipandtype, socktypeandprotos);

	tmpport = node->ports;

	while(tmpport && *tmpport) {
		if (!(node->all_low_ports && **tmpport < 1024) &&
		    !(node->all_high_ports && **tmpport >= 1024))
			fprintf(stream, "%s:%u%s\n", ipandtype, **tmpport, socktypeandprotos);
		tmpport++;
	}

	return 0;
}

int display_only_ip(struct gr_learn_ip_node *node, struct gr_learn_ip_node **unused, __u8 unused2,
		    FILE *stream)
{
	struct gr_learn_ip_node *saved = node;
	int depth = count_ip_depth(node);
	__u8 ip[4];
	int netmask = 0;
	int i;

	if (node->leaves)
		return 0;

	if (!node->root_node)
		netmask = 8 * depth;
	else {
		ip[0] = ip[1] = ip[2] = ip[3] = 0;
		goto print_ip;
	}

	for(i = 3; i >= 0; i--) {
		if (depth < (i + 1))
			ip[i] = 0;
		else {
			ip[i] = node->ip_node;
			node = node->parent;
		}
	}

print_ip:
	node = saved;
	fprintf(stream, "role_allow_ip\t%u.%u.%u.%u/%u\n", ip[0], ip[1], ip[2], ip[3], netmask);

	return 0;
}

void display_ip_tree(struct gr_learn_ip_node *base, __u8 contype, FILE *stream)
{
	traverse_ip_tree(base, NULL, &display_ip_node, contype, stream);
	return;
}

unsigned long count_ports(__u16 **ports)
{
	unsigned long ret = 0;

	if (!ports)
		return ret;

	while (*ports) {
		ports++;
		ret++;
	}

	return ret;
}		
		
unsigned long count_ips(struct gr_learn_ip_node **ips)
{
	unsigned long ret = 0;

	if (!ips)
		return ret;

	while (*ips) {
		ips++;
		ret++;
	}

	return ret;
}

int analyze_ip_node(struct gr_learn_ip_node *node)
{
	int depth = count_ip_depth(node);
	unsigned long num_ips = count_total_ips(node);
	unsigned long analysis_factor = (depth + 1) * num_ips;

	if (analysis_factor > 19)
		return 1;
	else
		return 0;
}

void insert_port(struct gr_learn_ip_node *node, __u16 port)
{
	__u16 **tmpport;
	unsigned long num;

	tmpport = node->ports;

	num = count_ports(tmpport);

	while(tmpport && *tmpport) {
		if (**tmpport == port)
			return;
		tmpport++;
	}

	if (!num) {
		node->ports = calloc(2, sizeof(__u16 *));
		if (!node->ports)
			failure("calloc");
		*(node->ports) = calloc(1, sizeof(__u16));
		if (!(*(node->ports)))
			failure("calloc");
		**(node->ports) = port;
	} else {
		node->ports = realloc(node->ports, (num + 2) * sizeof(__u16 *));
		if (!node->ports)
			failure("realloc");
		memset(node->ports + num, 0, 2 * sizeof(__u16 *));
		*(node->ports + num) = calloc(1, sizeof(__u16));
		if (!(*(node->ports + num)))
			failure("calloc");
		**(node->ports + num) = port;
	}

	return;
}

void remove_port(struct gr_learn_ip_node *node, __u16 port)
{
	__u16 **ports = node->ports;
	unsigned long num = count_ports(ports);
	unsigned long i;

	for(i = 0; i < num; i++) {
		if (**(ports + i) == port) {
			while (i < num) {
				**(ports + i) = **(ports + i + 1);
				i++;
			}
		}
	}

	return;
}

void do_reduce_ip_node(struct gr_learn_ip_node *node, struct gr_learn_ip_node *actor)
{
	__u16 **tmpport = node->ports;
	struct gr_learn_ip_node **tmpip;
	int i;

	while (tmpport && *tmpport) {
		insert_port(actor, **tmpport);
		free(*tmpport);
		*tmpport = NULL;
		tmpport++;
	}
	if (node->ports) {
		free(node->ports);
		node->ports = NULL;
	}

	for (i = 0; i < (sizeof(node->ip_proto)/sizeof(node->ip_proto[0])); i++)
		actor->ip_proto[i] |= node->ip_proto[i];
	actor->ip_type |= node->ip_type;

	if (!node->leaves) {
		free(node);
		return;
	}

	tmpip = node->leaves;

	while(*tmpip) {
		do_reduce_ip_node(*tmpip, actor);
		tmpip++;
	}

	free(node->leaves);
	node->leaves = NULL;

	return;
}



int reduce_ip_node(struct gr_learn_ip_node *node, struct gr_learn_ip_node **actor, __u8 unused1,
		   FILE *unused2)
{
	
	if (analyze_ip_node(node)) {
		*actor = node;
		do_reduce_ip_node(node, *actor);
	}

	return 0;
}

int analyze_port_node(struct gr_learn_ip_node *node)
{
	unsigned long low_ports = 0, high_ports = 0;
	int ret = 0;
	__u16 **tmpport;

	tmpport = node->ports;

	while (tmpport && *tmpport) {
		if (**tmpport < 1024)
			low_ports++;
		else
			high_ports++;
		tmpport++;
	}

	if (low_ports > 5)
		ret += 1;
	if (high_ports > 4)
		ret += 2;

	return ret;
}	

int reduce_port_node(struct gr_learn_ip_node *node, struct gr_learn_ip_node **unused, __u8 unused1,
		     FILE *unused2)
{
	
	switch(analyze_port_node(node)) {
	case 1:
		node->all_low_ports = 1;
		break;
	case 2:
		node->all_high_ports = 1;
		break;
	case 3:
		node->all_low_ports = 1;
		node->all_high_ports = 1;
		break;
	}

	return 0;
}


void reduce_ip_tree(struct gr_learn_ip_node *base)
{
	struct gr_learn_ip_node *tmp = NULL;

	traverse_ip_tree(base, &tmp, &reduce_ip_node, 0, NULL);
	return;
}

void reduce_ports_tree(struct gr_learn_ip_node *base)
{
	traverse_ip_tree(base, NULL, &reduce_port_node, 0, NULL);
	return;
}

__u8 extract_ip_field(__u32 ip, unsigned long depth)
{
	__u8 ip_node[4];

	memcpy(ip_node, &ip, sizeof(ip));

	switch(depth) {
	case 3:
		return ip_node[0];
	case 2:
		return ip_node[1];
	case 1:
		return ip_node[2];
	case 0:
		return ip_node[3];
	default:
		return 0;
	}

}

struct gr_learn_ip_node ** find_insert_ip(struct gr_learn_ip_node **base, __u32 ip,
					  struct gr_learn_ip_node **parent)
{
	struct gr_learn_ip_node *** node = NULL;
	struct gr_learn_ip_node **tmpip = NULL;
	int depth = 0;
	unsigned long num_ips = 0;
	int match = 0;

	if (!(*base)) {
		(*base) = calloc(1, sizeof(struct gr_learn_ip_node));
		if (!(*base))
			failure("calloc");
		(*base)->root_node = 1;
	}

	depth = count_ip_depth(*base);
	node = &((*base)->leaves);

	tmpip = *node;
	while (tmpip && *tmpip) {
		if ((*tmpip)->ip_node == extract_ip_field(ip, depth)) {
			match = 1;
			break;
		}
		tmpip++;
	}

	if (match && depth < 3) {
		return find_insert_ip(tmpip, ip, parent);
	} else if (match)
		return tmpip;
	else {
		num_ips = count_ips(*node);
		(*node) = realloc((*node), (2 + num_ips) * sizeof(struct gr_learn_ip_node *));
		if (!(*node))
			failure("realloc");
		memset((*node) + num_ips, 0, 2 * sizeof(struct gr_learn_ip_node *));

		if (depth == 3) {
			*parent = *base;
			return ((*node) + num_ips);
		} else {
			(*((*node) + num_ips)) = calloc(1, sizeof(struct gr_learn_ip_node));
			if (!(*((*node) + num_ips)))
				failure("calloc");
			(*((*node) + num_ips))->ip_node = extract_ip_field(ip, depth);
			(*((*node) + num_ips))->parent = *base;
			return find_insert_ip(((*node) + num_ips), ip, parent);
		}
	}
}


void insert_ip(struct gr_learn_ip_node **base, __u32 ip, __u16 port, __u8 proto,
		__u8 socktype)
{
	struct gr_learn_ip_node **node;
	struct gr_learn_ip_node *parent = NULL;
	struct gr_learn_ip_node *insert;
	__u8 ip_node[4];

	insert = calloc(1, sizeof(struct gr_learn_ip_node));
	if (!insert)
		failure("calloc");

	insert_port(insert, port);
	insert->ip_proto[proto / 32] = (1 << (proto % 32));
	insert->ip_type |= (1 << socktype);
	memcpy(&ip_node, &ip, sizeof(ip));
	insert->ip_node = ip_node[0];

	node = find_insert_ip(base, ip, &parent);

	if (*node) {
		(*node)->ip_proto[proto / 32] |= (1 << (proto % 32));
		(*node)->ip_type |= (1 << socktype);
		insert_port(*node, port);
		free(insert);
		return;
	} else {
		*node = insert;
		(*node)->parent = parent;
	}

	return;
}

static int strcompare(const void *x, const void *y)
{
        struct gr_learn_file_tmp_node *x1 = *(struct gr_learn_file_tmp_node **) x;
        struct gr_learn_file_tmp_node *y1 = *(struct gr_learn_file_tmp_node **) y;

        return strcmp(x1->filename, y1->filename);
}

void sort_file_list(struct gr_learn_file_tmp_node **file_list)
{
	struct gr_learn_file_tmp_node **tmp;
	unsigned long num = 0;

	tmp = file_list;
	if (!tmp)
		return;
	while (*tmp) {
		num++;
		tmp++;
	}

	return qsort(file_list, num, sizeof (struct gr_learn_file_tmp_node *), strcompare);
}

void insert_temp_file(struct gr_learn_file_tmp_node ***file_list, char *filename, __u32 mode)
{
	unsigned long num = 0;

	if (!(*file_list)) {
		*file_list = calloc(2, sizeof(struct gr_learn_file_tmp_node *));
		if (!(*file_list))
			failure("calloc");
	} else {
		struct gr_learn_file_tmp_node **tmp;

		tmp = *file_list;
		while(*tmp) {
			if (!strcmp((*tmp)->filename, filename)) {
				(*tmp)->mode |= mode;
				return;
			}
			num++;
			tmp++;
		}
		*file_list = realloc(*file_list, (2 + num) * sizeof(struct gr_learn_file_tmp_node *));
		if (!(*file_list))
			failure("realloc");
		memset(*file_list + num, 0, 2 * sizeof(struct gr_learn_file_tmp_node *));
	}

	(*((*file_list) + num)) = calloc(1, sizeof(struct gr_learn_file_tmp_node));
	if (!(*((*file_list) + num)))
		failure("calloc");
	(*((*file_list) + num))->filename = filename;
	(*((*file_list) + num))->mode = mode;
	
	return;
}

struct gr_learn_role_entry *
insert_learn_role(struct gr_learn_role_entry ***role_list, char *rolename, __u16 rolemode)
{
	unsigned long num = 0;

	if (!(*role_list)) {
		*role_list = calloc(2, sizeof(struct gr_learn_role_entry *));
		if (!(*role_list))
			failure("calloc");
	} else {
		struct gr_learn_role_entry **tmp;

		tmp = *role_list;
		while(*tmp) {
			if (!strcmp((*tmp)->rolename, rolename)) {
				(*tmp)->rolemode |= rolemode;
				return *tmp;
			}
			num++;
			tmp++;
		}
		*role_list = realloc(*role_list, (2 + num) * sizeof(struct gr_learn_role_entry *));
		if (!(*role_list))
			failure("realloc");
		memset(*role_list + num, 0, 2 * sizeof(struct gr_learn_role_entry *));
	}

	(*((*role_list) + num)) = calloc(1, sizeof(struct gr_learn_role_entry));
	if (!(*((*role_list) + num)))
		failure("calloc");
	(*((*role_list) + num))->rolename = rolename;
	(*((*role_list) + num))->rolemode = rolemode;
	
	return (*((*role_list) + num));
}

struct gr_learn_role_entry *
find_learn_role(struct gr_learn_role_entry **role_list, char *rolename)
{
	struct gr_learn_role_entry **tmp;

	tmp = role_list;
	while(tmp && *tmp) {
		if (!strcmp((*tmp)->rolename, rolename))
			return *tmp;
		tmp++;
	}
	return NULL;
}

