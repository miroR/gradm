#include "gradm.h"

static unsigned long *learn_queue = NULL;
static unsigned long learn_queue_size = 0;

static int
strcompare(const void *x, const void *y)
{
	struct learn_info *x1 = *(struct learn_info **) x;
	struct learn_info *y1 = *(struct learn_info **) y;
	return strcmp(x1->obj_name, y1->obj_name);
}

static void
sort_names(struct learn_info **obj_array, unsigned long num)
{
	return qsort(obj_array, num, sizeof (struct learn_info *), strcompare);
}

static int
has_similar_dir(const char *f1, const char *f2, unsigned int len)
{
	if (!strncmp(f2, f1, len) && (f2[len] == '/' || f2[len] == '\0'))
		return 1;

	return 0;
}

static void
set_common_dir(const char *fname, char **common_dir, unsigned int *len)
{
	unsigned int i;
	char *p;

	if (*fname != '/') {
		*len = 0;
		return;
	}

	for (i = strlen(fname) - 1; i >= 0; i--)
		if (fname[i] == '/')
			break;

	if (!i)
		i++;

	strncpy(*common_dir, fname, i);

	*len = i;
	p = *common_dir;
	p[i] = '\0';

	return;
}

static int
have_common_dir(const char *fname, char *common_dir, unsigned int len)
{
	unsigned int i;
	unsigned int namelen = strlen(fname);

	if (!namelen)
		return 0;

	for (i = namelen - 1; i >= 0; i--)
		if (fname[i] == '/')
			break;

	if (!i)
		i++;

	if (i != len)
		return 0;

	if (strncmp(fname, common_dir, len))
		return 0;

	return 1;
}

static void
remove_queue_items(void)
{
	unsigned long i;

	for (i = 0; i < learn_queue_size; i++) {
		free((*(learn_db + (*(learn_queue + i))))->obj_name);
		(*(learn_db + (*(learn_queue + i)))) = NULL;
	}

	return;
}

static void
add_to_remove_queue(unsigned long offset)
{
	if (!learn_queue)
		learn_queue =
		    (unsigned long *) calloc(1, sizeof (unsigned long));

	if (!learn_queue)
		failure("calloc");

	learn_queue =
	    realloc(learn_queue,
		    (learn_queue_size + 1) * sizeof (unsigned long));

	if (!learn_queue)
		failure("realloc");

	(*(learn_queue + learn_queue_size)) = offset;

	learn_queue_size++;

	return;
}

static void
clear_remove_queue(void)
{
	learn_queue_size = 0;
	learn_queue = NULL;
	return;
}

static int
learn_is_dupe(char *rolename, __u16 roletype, char *subjname,
	      unsigned long res_cur, unsigned long res_max,
	      char *obj_name, __u32 mode)
{
	struct learn_info **tmp_db;
	unsigned long i;

	tmp_db = learn_db;

	for (i = 0; i < learn_num; i++, tmp_db++) {
		if (!(*tmp_db))
			continue;

		if (!strcmp((*tmp_db)->obj_name, obj_name) &&
		    !strcmp((*tmp_db)->rolename, rolename) &&
		    !strcmp((*tmp_db)->subjname, subjname) &&
		    (*tmp_db)->roletype == roletype) {
			// capabilities and resources get special handling
			if (!strlen(obj_name)) {
				if (!res_cur && !res_max &&
				    !(*tmp_db)->res_cur &&
				    !(*tmp_db)->res_max &&
				    ((*tmp_db)->mode == mode))
					return 1;
				else if (res_cur && res_max &&
					 (*tmp_db)->res_cur &&
					 (*tmp_db)->res_max &&
					 (*tmp_db)->mode == mode) {
					if (res_cur > (*tmp_db)->res_cur)
						(*tmp_db)->res_cur = res_cur;
					if (res_max > (*tmp_db)->res_max)
						(*tmp_db)->res_max = res_max;
					return 1;
				}
				continue;
			}

			if ((*tmp_db)->mode != mode)
				(*tmp_db)->mode |= mode;

			return 1;
		}
	}

	return 0;
}

static void
insert_reduced_acl(unsigned long offset, char *common_dir,
		   unsigned long res_cur, unsigned long res_max,
		   char *rolename, __u16 roletype, char *subjname, __u32 mode)
{
	char *reduced_dir;

	reduced_dir = (char *) calloc(strlen(common_dir) + 1, sizeof (char));
	if (!reduced_dir)
		failure("calloc");

	strcpy(reduced_dir, common_dir);

	if (learn_is_dupe
	    (rolename, roletype, subjname, res_cur, res_max, reduced_dir,
	     mode)) {
		free(reduced_dir);
		free((*(learn_db + offset))->obj_name);
		(*(learn_db + offset)) = NULL;
		return;
	}

	(*(learn_db + offset))->rolename = rolename;
	(*(learn_db + offset))->roletype = roletype;
	(*(learn_db + offset))->subjname = subjname;
	(*(learn_db + offset))->res_cur = res_cur;
	(*(learn_db + offset))->res_max = res_max;
	(*(learn_db + offset))->mode = mode;
	(*(learn_db + offset))->obj_name = reduced_dir;

	return;
}

static void
reduce_acls(void)
{
	struct learn_info **tmp_db;
	unsigned long i;
	unsigned long x;
	char *common_dir;
	unsigned int common_len;
	unsigned long occur;

	if (!learn_num)
		return;

	common_dir = (char *) calloc(PATH_MAX, sizeof (char));

	if (!common_dir)
		failure("calloc");

	tmp_db = learn_db;

	for (i = 0; i < (learn_num - 1); i++) {
		x = 1;
		occur = 0;
		if (!(*(tmp_db + i)))
			continue;

		set_common_dir((*(tmp_db + i))->obj_name, &common_dir,
			       &common_len);
		if (!common_len)
			continue;

		while ((x < (learn_num - i)) &&
		       (((*(tmp_db + i + x)) && has_similar_dir(common_dir,
								(*
								 (tmp_db + i +
								  x))->obj_name,
								common_len))
			|| !(*(tmp_db + i + x)))) {
			if (!(*(tmp_db + i + x))) {
				x++;
				continue;
			}

			if (have_common_dir((*(tmp_db + x + i))->obj_name,
					    common_dir, common_len) &&
			    !strcmp((*(tmp_db + i))->rolename,
				    (*(tmp_db + x + i))->rolename) &&
			    !strcmp((*(tmp_db + i))->subjname,
				    (*(tmp_db + x + i))->subjname) &&
			    ((*(tmp_db + i))->roletype ==
			     (*(tmp_db + x + i))->roletype) &&
			    ((*(tmp_db + i))->mode ==
			     (*(tmp_db + x + i))->mode)) {
				occur++;
				add_to_remove_queue(i + x);
			}
			x++;
		}

		if (occur >= GR_LEARN_THRESH) {
			remove_queue_items();
			insert_reduced_acl(i, common_dir,
					   (*(tmp_db + i))->res_cur,
					   (*(tmp_db + i))->res_max,
					   (*(tmp_db + i))->rolename,
					   (*(tmp_db + i))->roletype,
					   (*(tmp_db + i))->subjname,
					   (*(tmp_db + i))->mode);
		}
		clear_remove_queue();
	}

	free(common_dir);
	return;
}

int
learn_ip_is_dupe(char *rolename, __u16 roletype, char *subjname,
		 unsigned long ip, __u16 port, __u16 sock, __u16 proto,
		 __u16 mode)
{
	struct ip_learn_info **tmp_db;
	unsigned long i;

	tmp_db = ip_learn_db;

	for (i = 0; i < ip_learn_num; i++, tmp_db++) {
		if (!strcmp((*tmp_db)->subjname, subjname) &&
		    !strcmp((*tmp_db)->rolename, rolename) &&
		    ((*tmp_db)->roletype == roletype) &&
		    ((*tmp_db)->addr == ip) &&
		    ((*tmp_db)->port == port) &&
		    ((*tmp_db)->sock == sock) &&
		    ((*tmp_db)->proto == proto) && ((*tmp_db)->mode == mode))
			return 1;
	}

	return 0;
}

void
add_learn_ip_info(char *rolename, __u16 roletype, char *subjname,
		  __u32 ip, __u16 port, __u16 sock, __u16 proto, __u16 mode)
{
	struct ip_learn_info **tmp_db;

	if (learn_ip_is_dupe
	    (rolename, roletype, subjname, ip, port, sock, proto, mode))
		return;

	if ((ip_learn_db =
	     (struct ip_learn_info **) realloc(ip_learn_db,
					       (ip_learn_num +
						1) *
					       sizeof (struct ip_learn_info *)))
	    == NULL)
		failure("calloc");

	tmp_db = ip_learn_db + ip_learn_num;

	*tmp_db =
	    (struct ip_learn_info *) calloc(1, sizeof (struct ip_learn_info));

	if (!(*tmp_db))
		failure("calloc");

	(*tmp_db)->subjname = subjname;
	(*tmp_db)->addr = ip;
	(*tmp_db)->port = port;
	(*tmp_db)->sock = sock;
	(*tmp_db)->proto = proto;
	(*tmp_db)->mode = mode;

	ip_learn_num++;

	return;
}

void
add_learn_file_info(char *rolename, __u16 roletype, char *subjname,
		    unsigned long res_cur, unsigned long res_max,
		    char *obj_name, __u32 mode)
{
	struct learn_info **tmp_db;
	char *p;

	if (!obj_name) {
		fprintf(stderr, "Out of memory.\n");
		exit(EXIT_FAILURE);
	}

	if ((p = strstr(obj_name, " (deleted)")))
		*p = '\0';

	if (learn_is_dupe
	    (rolename, roletype, subjname, res_cur, res_max, obj_name, mode)) {
		free(obj_name);
		return;
	}

	if ((learn_db =
	     (struct learn_info **) realloc(learn_db,
					    (learn_num +
					     1) *
					    sizeof (struct learn_info *))) ==
	    NULL)
		failure("calloc");

	tmp_db = learn_db + learn_num;

	*tmp_db = (struct learn_info *) calloc(1, sizeof (struct learn_info));

	if (!(*tmp_db))
		failure("calloc");

	(*tmp_db)->rolename = rolename;
	(*tmp_db)->roletype = roletype;
	(*tmp_db)->subjname = subjname;
	(*tmp_db)->res_cur = res_cur;
	(*tmp_db)->res_max = res_max;
	(*tmp_db)->obj_name = obj_name;
	(*tmp_db)->mode = mode;
	/* to be able to perform an operation on the file, we have to be
	   able to view it */
	if (strlen(obj_name))	// check if it's a file
		(*tmp_db)->mode |= GR_FIND;

	learn_num++;

	return;
}

void
merge_acl_rules(void)
{
	unsigned long i;
	struct proc_acl *proc;
	struct role_acl *role;

	for_each_role(role, current_role) {
		for_each_subject(proc, role) {
			if (!(proc->mode & GR_LEARN))
				continue;

			for (i = 0; i < learn_num; i++) {
				if (!(*(learn_db + i)))
					continue;

				if (!strcmp
				    ((*(learn_db + i))->subjname,
				     proc->filename)
				    && !strcmp((*(learn_db + i))->rolename,
					       role->rolename)
				    && ((*(learn_db + i))->roletype ==
					role->roletype)) {
					/* ok, we found matching processes,
					   let's add the rule. */
					if (!strlen((*(learn_db + i))->obj_name)
					    && !((*(learn_db + i))->res_cur)
					    && !((*(learn_db + i))->res_max))
						modify_caps(proc,
							    (*(learn_db + i))->
							    mode);
					else if (!strlen
						 ((*(learn_db + i))->obj_name))
						modify_res(proc,
							   (*(learn_db + i))->
							   mode,
							   (*(learn_db + i))->
							   res_cur,
							   (*(learn_db + i))->
							   res_max);
					else
						add_proc_object_acl(proc,
								    (*
								     (learn_db +
								      i))->
								    obj_name,
								    (*
								     (learn_db +
								      i))->mode,
								    GR_FLEARN);
				}
			}

			for (i = 0; i < ip_learn_num; i++) {
				if (!strcmp
				    ((*(ip_learn_db + i))->subjname,
				     proc->filename)
				    && !strcmp((*(ip_learn_db + i))->rolename,
					       role->rolename)
				    && ((*(learn_db + i))->roletype ==
					role->roletype)) {
					struct ip_acl tmp_ip;
					memset(&tmp_ip, 0, sizeof (tmp_ip));

					tmp_ip.addr =
					    (*(ip_learn_db + i))->addr;
					tmp_ip.low = (*(ip_learn_db + i))->port;
					tmp_ip.high =
					    (*(ip_learn_db + i))->port;

					tmp_ip.netmask = 0xffffffff;
					tmp_ip.type |=
					    (1 << (*(ip_learn_db + i))->sock);
					tmp_ip.proto[(*(ip_learn_db + i))->
						     proto / 32] |=
					    (1 <<
					     ((*(ip_learn_db + i))->proto %
					      32));
					tmp_ip.mode =
					    (*(ip_learn_db + i))->mode;

					if ((*(ip_learn_db + i))->mode ==
					    GR_IP_BIND)
						add_ip_acl(proc, GR_IP_BIND,
							   &tmp_ip);
					else if ((*(ip_learn_db + i))->mode ==
						 GR_IP_CONNECT)
						add_ip_acl(proc, GR_IP_CONNECT,
							   &tmp_ip);
				}
			}
		}
	}

	return;
}

void
handle_learn_logs(const char *file, FILE * stream)
{
	parse_learn_log(file);
	sort_names(learn_db, learn_num);
	reduce_acls();
	parse_acls();
	expand_acls();
	merge_acl_rules();
	pass_struct_to_human(stream);

	return;
}
