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

extern FILE *gradmin;
extern int gradmparse(void);

void set_role_umask(struct role_acl *role, u_int16_t umask)
{
	role->umask = umask;
}

char *strip_trailing_slash(char *filename)
{
	unsigned int file_len = strlen(filename);
	if (file_len > 1 && filename[file_len - 1] == '/')
		filename[file_len - 1] = '\0';

	if (file_len >= PATH_MAX) {
		fprintf(stderr, "Filename too long on line %lu of file %s.\n",
			lineno, current_acl_file);
		exit(EXIT_FAILURE);
	}

	return filename;
}

static int get_id_from_role_name(const char *rolename, u_int16_t type, int *retid)
{
	unsigned long the_id = 0;
	struct passwd *pwd;
	struct group *grp;
	char *endptr;

	if (type & GR_ROLE_USER) {
		pwd = getpwnam(rolename);

		if (!pwd) {
			/* now try it as a uid */
			the_id = strtoul(rolename, &endptr, 10);
			if (*endptr == '\0')
				pwd = getpwuid((int)the_id);
			if (the_id > INT_MAX || *endptr != '\0') {
				fprintf(stderr, "Warning: User %s on line %lu of %s "
					"is invalid.\n", rolename,
					lineno, current_acl_file);
				return 1;
			}
		}
		if (pwd)
			the_id = pwd->pw_uid;
		/* else, the_id obtained above via strtoul is valid */
	} else if (type & GR_ROLE_GROUP) {
		grp = getgrnam(rolename);

		if (!grp) {
			/* now try it as a gid */
			the_id = strtoul(rolename, &endptr, 10);
			if (*endptr == '\0')
				grp = getgrgid((int)the_id);
			if (the_id > INT_MAX || *endptr != '\0') {
				fprintf(stderr, "Warning: Group %s on line %lu of %s "
					"is invalid.\n", rolename,
					lineno, current_acl_file);
				return 1;
			}
		}
		if (grp)
			the_id = grp->gr_gid;
		/* else, the_id obtained above via strtoul is valid */
	}

	*retid = (int)the_id;
	return 0;
}

void
add_id_transition(struct proc_acl *subject, const char *idname, int usergroup, int allowdeny)
{
	int i;
	int id;
	int ret;

	if (usergroup == GR_ID_USER) {
		if ((subject->user_trans_type | allowdeny) == (GR_ID_ALLOW | GR_ID_DENY)) {
			fprintf(stderr, "Error on line %lu of %s.  You cannot use "
				"both user_transition_allow and user_transition_deny.\n"
				"The RBAC system will not be allowed to be enabled until "
				"this error is fixed.\n", lineno, current_acl_file);
			exit(EXIT_FAILURE);
		}
		subject->user_trans_type |= allowdeny;

		ret = get_id_from_role_name(idname, GR_ROLE_USER, &id);
		if (ret)
			return;

		/* dupecheck */
		for (i = 0; i < subject->user_trans_num; i++)
			if (subject->user_transitions[i] == id)
				return;

		/* increment pointer count upon allocation of user transition list */
		if (subject->user_transitions == NULL)
			num_pointers++;

		subject->user_trans_num++;
		subject->user_transitions = (uid_t *)gr_realloc(subject->user_transitions, subject->user_trans_num * sizeof(uid_t));
		subject->user_transitions[subject->user_trans_num - 1] = id;
	} else if (usergroup == GR_ID_GROUP) {
		if ((subject->group_trans_type | allowdeny) == (GR_ID_ALLOW | GR_ID_DENY)) {
			fprintf(stderr, "Error on line %lu of %s.  You cannot use "
				"both group_transition_allow and group_transition_deny.\n"
				"The RBAC system will not be allowed to be enabled until "
				"this error is fixed.\n", lineno, current_acl_file);
			exit(EXIT_FAILURE);
		}
		subject->group_trans_type |= allowdeny;

		ret = get_id_from_role_name(idname, GR_ROLE_GROUP, &id);
		if (ret)
			return;

		/* dupecheck */
		for (i = 0; i < subject->group_trans_num; i++)
			if (subject->group_transitions[i] == id)
				return;

		/* increment pointer count upon allocation of group transition list */
		if (subject->group_transitions == NULL)
			num_pointers++;

		subject->group_trans_num++;
		subject->group_transitions = (gid_t *)gr_realloc(subject->group_transitions, subject->group_trans_num * sizeof(gid_t));
		subject->group_transitions[subject->group_trans_num - 1] = id;
	}

	return;
}

static int
is_role_dupe(struct role_acl *role, const char *rolename, const u_int16_t type)
{
	struct role_acl *tmp;
	int id = 0;
	int ret;
	int i;

	if ((type & GR_ROLE_ISID) || ((type & (GR_ROLE_USER | GR_ROLE_GROUP)) && !(type & GR_ROLE_DOMAIN))) {
		ret = get_id_from_role_name(rolename, type, &id);
		if (ret)
			return 0;
	}

	for_each_role(tmp, role) {
		if ((tmp->roletype & (GR_ROLE_USER | GR_ROLE_GROUP | GR_ROLE_SPECIAL) & type) && !strcmp(tmp->rolename, rolename))
			return 1;
		if ((tmp->roletype & GR_ROLE_DOMAIN) && (type & (GR_ROLE_USER | GR_ROLE_GROUP))) {
			for (i = 0; i < tmp->domain_child_num; i++) {
				if (tmp->domain_children[i] == id)
					return 1;
			}
	    	}
	}

	return 0;
}

void
add_domain_child(struct role_acl *role, const char *idname)
{
	int ret, id;

	if (!(role->roletype & (GR_ROLE_USER | GR_ROLE_GROUP))) {
		// should never get here
		fprintf(stderr, "Unhandled exception 1.\n");
		exit(EXIT_FAILURE);
	}

	if (is_role_dupe(current_role, idname, role->roletype | GR_ROLE_ISID)) {
		fprintf(stderr, "Duplicate role %s on line %lu of %s.\n"
			"The RBAC system will not be allowed to be "
			"enabled until this error is fixed.\n",
			idname, lineno, current_acl_file);
		exit(EXIT_FAILURE);
	}

	ret = get_id_from_role_name(idname, role->roletype, &id);
	if (ret)
		return;

	/* reason for this is that in the kernel, the hash table which is keyed by UID/GID
	   has a size dependent on the number of roles.  Since we want to fake a domain
	   as being a real role for each of those users/groups by providing a pointer
	   to the domain for each user/group, we need to count each of these against the
	   role count */
	num_domain_children++;

	/* increment pointer count upon allocation of domain list */
	if (role->domain_children == NULL)
		num_pointers++;

	role->domain_child_num++;
	role->domain_children = (gid_t *)gr_realloc(role->domain_children, role->domain_child_num * sizeof(gid_t));
	*(role->domain_children + role->domain_child_num - 1) = id;

	return;
}

void
add_role_transition(struct role_acl *role, const char *rolename)
{
	struct role_transition **roletpp;
	struct role_transition *roletp;

	/* one for transition, one for name */
	num_pointers += 2;

	roletp = (struct role_transition *) gr_alloc(sizeof (struct role_transition));

	roletpp = &(role->transitions);

	if (*roletpp)
		(*roletpp)->next = roletp;

	roletp->prev = *roletpp;

	roletp->rolename = rolename;

	*roletpp = roletp;

	return;
}

void add_symlink(struct proc_acl *subj, struct file_acl *obj)
{
	struct symlink *sym = (struct symlink *)gr_alloc(sizeof (struct symlink));

	sym->role = current_role;
	sym->subj = subj;
	sym->obj = obj;
	sym->policy_file = current_acl_file;
	sym->lineno = lineno;

	sym->next = symlinks;
	symlinks = sym;

	return;
}

static struct deleted_file *
is_deleted_file_dupe(const char *filename)
{
	struct deleted_file *tmp;

	for (tmp = deleted_files; tmp; tmp = tmp->next) {
		if (!strcmp(filename, tmp->filename))
			return tmp;
	}

	return NULL;
}

static struct deleted_file *
add_deleted_file(const char *filename)
{
	struct deleted_file *dfile;
	struct deleted_file *retfile;
	static u_int64_t ino = 0x10000000;

	ino++;

	retfile = is_deleted_file_dupe(filename);
	if (retfile)
		return retfile;
	dfile = (struct deleted_file *)gr_alloc(sizeof (struct deleted_file));
	dfile->filename = filename;
	dfile->ino = ++ino;
	dfile->next = deleted_files;
	deleted_files = dfile;

	return deleted_files;
}

static struct file_acl *
is_proc_object_dupe(struct proc_acl *subject, struct file_acl *object)
{
	struct file_acl *tmp = NULL;

	tmp = lookup_acl_object_by_name(subject, object->filename);
	if (tmp == NULL)
		tmp = lookup_acl_object(subject, object);
	else {
		/* found a match by filename, handle 'Z' flag here */
		if (object->mode & GR_OBJ_REPLACE)
			tmp->mode = object->mode &~ GR_OBJ_REPLACE;
	}

	return tmp;
}

static struct proc_acl *
is_proc_subject_dupe(struct role_acl *role, struct proc_acl *subject)
{
	struct proc_acl *tmp = NULL;

	tmp = lookup_acl_subject_by_name(role, subject->filename);
	if (tmp == NULL)
		tmp = lookup_acl_subject(role, subject);
	else {
		/* found a match by filename, handle 'Z' flag here */
		if (subject->mode & GR_SUBJ_REPLACE) {
			// FIXME: we leak allocations here
			/* save off the old ->prev and restore it */
			struct proc_acl *prev = tmp->prev;
			memcpy(tmp, subject, sizeof(struct proc_acl));
			tmp->prev = prev;
			tmp->mode = subject->mode &~ GR_SUBJ_REPLACE;
			tmp->hash = create_hash_table(GR_HASH_OBJECT);
			current_subject = tmp;
		}
	}

	return tmp;
}

int
add_role_acl(struct role_acl **role, const char *rolename, u_int16_t type, int ignore)
{
	struct role_acl *rtmp;
	int id, ret;

	if (current_role && current_role->hash == NULL) {
		fprintf(stderr, "Error on line %lu of %s: "
				"Attempting to add the role \"%s\" when "
				"no subjects have been specified for "
				"the previous role \"%s\".\nThe RBAC "
				"system will not be allowed to be "
				"enabled until this error is fixed.\n", 
			lineno, current_acl_file, rolename, current_role->rolename);
		exit(EXIT_FAILURE);
	}

	num_roles++;

	/* one for role, one for name */
	num_pointers += 2;

	if (!rolename) {
		fprintf(stderr, "Out of memory.\n");
		exit(EXIT_FAILURE);
	}

	rtmp = (struct role_acl *) gr_alloc(sizeof (struct role_acl));

	rtmp->umask = 0;
	rtmp->roletype = type;
	rtmp->rolename = rolename;

	if (strcmp(rolename, "default") && (type & GR_ROLE_DEFAULT)) {
		fprintf(stderr, "No role type specified for %s on line %lu "
			"of %s.\nThe RBAC system will not be allowed to be "
			"enabled until this error is fixed.\n", rolename,
			lineno, current_acl_file);
		exit(EXIT_FAILURE);
	}

	if (is_role_dupe(*role, rtmp->rolename, rtmp->roletype)) {
		fprintf(stderr, "Duplicate role %s on line %lu of %s.\n"
			"The RBAC system will not be allowed to be "
			"enabled until this error is fixed.\n",
			rtmp->rolename, lineno, current_acl_file);
		exit(EXIT_FAILURE);
	}

	if (ignore)
		rtmp->uidgid = special_role_uid++;
	else if (strcmp(rolename, "default") || !(type & GR_ROLE_DEFAULT)) {
		if (type & (GR_ROLE_USER | GR_ROLE_GROUP)) {
			ret = get_id_from_role_name(rolename, type, &id);
			if (ret) {
				/* ignore roles for nonexistent users/groups */
				rtmp->roletype |= GR_ROLE_IGNORENOEXIST;
				num_roles--;
				num_pointers -= 2;
				id = -1;
			}
			rtmp->uidgid = id;
		} else if (type & GR_ROLE_SPECIAL) {
			rtmp->uidgid = special_role_uid++;
		}
	}

	if (*role)
		(*role)->next = rtmp;

	rtmp->prev = *role;

	*role = rtmp;

	if (type & GR_ROLE_SPECIAL)
		add_role_transition(rtmp,rolename);

	if (type & GR_ROLE_AUTH) {
		add_gradm_acl(rtmp);
		add_gradm_pam_acl(rtmp);
	}
	if (!(type & GR_ROLE_SPECIAL))
		add_grlearn_acl(rtmp);
	if (type & GR_ROLE_LEARN)
		add_rolelearn_acl();

	return 1;
}

int count_slashes(const char *str)
{
	int i = 0;
	while (*str) {
		if (*str == '/')
			i++;
		str++;
	}

	return i;
}

static int
add_globbing_file(struct proc_acl *subject, const char *filename,
		  u_int32_t mode, int type)
{
	struct glob_file *glob = (struct glob_file *)gr_alloc(sizeof (struct glob_file));

	glob->role = current_role;
	glob->subj = subject;
	glob->filename = filename;
	glob->mode = mode;
	glob->type = type;
	glob->policy_file = current_acl_file;
	glob->lineno = lineno;
	glob->next = NULL;

	
	if (!glob_files_head) {
		glob_files_head = glob;
	} else {
		glob_files_tail->next = glob;
	}

	glob_files_tail = glob;

	return 1;
}

int
add_globbed_object_acl(struct proc_acl *subject, const char *filename,
		  u_int32_t mode, int type, const char *policy_file, unsigned long line)
{
	char *basepoint;
	char *p, *p2;
	struct file_acl *anchor;
	struct file_acl *glob, *glob2;
	int lnum, onum;

	/* one for the object itself, one for the filename */
	num_pointers += 2;

	basepoint = get_anchor(filename);
	anchor = lookup_acl_object_by_name(subject, basepoint);

	if (!anchor) {
		fprintf(stderr, "Error on line %lu of %s:\n"
			"Object %s needs to be specified in the same subject as globbed object %s.\n"
			"The RBAC system will not be allowed to be enabled until this error is corrected.\n\n",
			line, policy_file, basepoint, filename);
		exit(EXIT_FAILURE);
	}

	free(basepoint);

	if (anchor->globbed) {
		glob = anchor->globbed;
		glob2 = (struct file_acl *)gr_alloc(sizeof(struct file_acl));
		onum = count_slashes(filename);
		lnum = count_slashes(glob->filename);
		if (onum > lnum) {
			glob2->next = glob;
			anchor->globbed = glob2;
			glob2->filename = filename;
			glob2->mode = mode;
			glob->prev = glob2;
			return 1;
		}
		while (glob->next) {
			lnum = count_slashes(glob->next->filename);
			if (onum > lnum) {
				glob2->next = glob->next;
				glob->next = glob2;
				glob2->filename = filename;
				glob2->mode = mode;
				glob2->prev = glob;
				glob->next->prev = glob2;
				return 1;
			}
			glob = glob->next;
		}
		glob2->filename = filename;
		glob2->mode = mode;
		glob2->prev = glob;
		glob->next = glob2;
	} else {
		glob2 = (struct file_acl *)gr_alloc(sizeof(struct file_acl));
		glob2->filename = filename;
		glob2->mode = mode;
		anchor->globbed = glob2;
	}

	return 1;
}

static void
display_all_dupes(struct proc_acl *subject, struct file_acl *filp2)
{
	struct file_acl *tmp;
	struct stat64 fstat;
	struct file_acl ftmp;

	for_each_file_object(tmp, subject) {
	    if (get_canonical_inodev(tmp->filename, &ftmp.inode, &ftmp.dev, NULL)) {
		if (ftmp.inode == filp2->inode && ftmp.dev == filp2->dev)
			fprintf(stderr, "%s (due to symlinking/hardlinking)\n", tmp->filename);
	    } else if (!strcmp(tmp->filename, filp2->filename)) {
		fprintf(stderr, "%s\n", tmp->filename);
	    }
	}
	return;
}

static char *
parse_homedir(const char *filename)
{
	struct passwd *pwd;
	unsigned int newlen;
	char *newfilename;

	if (!(current_role->roletype & GR_ROLE_USER) ||
	     (current_role->roletype & GR_ROLE_DOMAIN)) {
		fprintf(stderr, "Error on line %lu of %s.  $HOME "
				"is supported only on user roles.\n",
				lineno, current_acl_file);
		exit(EXIT_FAILURE);
	}

	pwd = getpwuid(current_role->uidgid);

	if (pwd == NULL) {
		fprintf(stderr, "Error: Unable to use $HOME on line %lu of %s"
			", as it can only be used in roles for users that exist"
			" at the time RBAC policy is enabled.\n", lineno, current_acl_file);
		exit(EXIT_FAILURE);
	}

	newlen = strlen(pwd->pw_dir) + strlen(filename) - 5 + 1;

	newfilename = (char *)gr_alloc(newlen);

	if (!newfilename) {
		fprintf(stderr, "Out of memory.\n");
		exit(EXIT_FAILURE);
	}

	strcpy(newfilename, pwd->pw_dir);
	strcat(newfilename, (filename + 5));

	return newfilename;
}

int
add_proc_object_acl(struct proc_acl *subject, const char *filename,
		    u_int32_t mode, int type)
{
	struct file_acl *p;
	struct file_acl *p2;
	struct deleted_file *dfile;
	const char *str;
	u_int64_t inode;
	u_int32_t dev;
	int is_symlink;

	if (!subject) {
		fprintf(stderr, "Error on line %lu of %s.  Attempt to "
			"add an object without a subject declaration.\n"
			"The RBAC system will not load until this "
			"error is fixed.\n", lineno, current_acl_file);
		exit(EXIT_FAILURE);
	}

	if (!filename) {
		fprintf(stderr, "Out of memory.\n");
		exit(EXIT_FAILURE);
	}

	if (!strncmp(filename, "$HOME", 5))
		filename = parse_homedir(filename);
	else if (!strncmp(filename, "/dev/pts/", 9)) {
		fprintf(stderr, "Error on line %lu of %s.  Grsecurity does "
				"not support fine-grained policy on devpts mounts.\n"
				"Please change your more fine-grained object to a /dev/pts "
				"object.  This will in addition produce a better policy that "
				"will not break as unnecessarily.\n"
				"The RBAC system will not load until this "
				"error is fixed.\n", lineno, current_acl_file);
		exit(EXIT_FAILURE);
	}

	str = filename;
	if (!strncmp(filename, "/SYSV", 5))
		return add_globbing_file(subject, filename, mode, type);
	while (*str) {
		if (*str == '?' || *str == '*')
			return add_globbing_file(subject, filename, mode, type);
		if (*str == '[') {
			const char *str2 = str;
			while (*str2) {
				if (*str2 == ']')
					return add_globbing_file(subject, filename, mode, type);
				str2++;
			}
		}
		str++;
	}

	if (!get_canonical_inodev(filename, &inode, &dev, &is_symlink)) {
		dfile = add_deleted_file(filename);
		inode = dfile->ino;
		dev = 0;
		mode |= GR_DELETED;
	}

	num_objects++;
	/* one for the object, one for the filename, one for the name entry struct, and one for the inodev_entry struct in the kernel*/
	num_pointers += 4;

	p = (struct file_acl *) gr_alloc(sizeof (struct file_acl));

	p->filename = filename;
	p->mode = mode;
	p->inode = inode;
	p->dev = dev;

	if (type & GR_FLEARN) {
		struct file_acl *tmp;

		tmp = lookup_acl_object_by_name(subject, p->filename);
		if (tmp) {
			tmp->mode |= mode;
			return 1;
		}
		tmp = lookup_acl_object(subject, p);
		if (tmp) {
			tmp->mode |= mode;
			return 1;
		}
	} else if ((p2 = is_proc_object_dupe(subject, p))) {
		if (p2->mode == mode)
			return 1;
		fprintf(stderr, "Duplicate object found for \"%s\""
			" in role %s, subject %s, on line %lu of %s.\n"
			"\"%s\" references the same object as the following object(s):\n",
			p->filename, current_role->rolename, 
			subject->filename, lineno, 
			current_acl_file ? current_acl_file : "<builtin_fulllearn_policy>", p->filename);
		display_all_dupes(subject, p);
		fprintf(stderr, "specified on an earlier line.\n");
		fprintf(stderr, "The RBAC system will not load until this error is fixed.\n");
		exit(EXIT_FAILURE);
	}

	insert_acl_object(subject, p);

	if (is_symlink)
		add_symlink(subject, p);

	return 1;
}

int
add_proc_subject_acl(struct role_acl *role, const char *filename, u_int32_t mode, int flag)
{
	struct proc_acl *p;
	struct proc_acl *p2;
	struct deleted_file *dfile;
	struct stat fstat;

	num_subjects++;
	/* one for the subject, one for the filename */
	num_pointers += 2;

	if (!role) {
		fprintf(stderr, "Error on line %lu of %s.  Attempt to "
			"add a subject without a role declaration.\n"
			"The RBAC system will not load until this "
			"error is fixed.\n", lineno, current_acl_file);
		exit(EXIT_FAILURE);
	}

	if (!filename) {
		fprintf(stderr, "Out of memory.\n");
		exit(EXIT_FAILURE);
	}

	if (mode & GR_LEARN && mode & GR_INHERITLEARN) {
		fprintf(stderr, "Error on line %lu of %s.  Subject mode "
			"may not include both learn and inherit-learn.\n"
			"The RBAC system will not load until this "
			"error is fixed.\n", lineno, current_acl_file);
		exit(EXIT_FAILURE);
	}

	if (!strncmp(filename, "$HOME", 5))
		filename = parse_homedir(filename);

	p = (struct proc_acl *) gr_alloc(sizeof (struct proc_acl));

	// FIXME: for subjects we currently follow symlinks
	if (!get_canonical_inodev(filename, &p->inode, &p->dev, NULL)) {
		dfile = add_deleted_file(filename);
		p->inode = dfile->ino;
		p->dev = 0;
		mode |= GR_DELETED;
	}

	if (!strcmp(filename, "/") && !(flag & GR_FFAKE))
		role->root_label = p;

	p->filename = filename;
	p->mode = mode;

	if (!(flag & GR_FFAKE) && (p2 = is_proc_subject_dupe(role, p))) {
		if (mode & GR_SUBJ_REPLACE)
			return 1;
		fprintf(stderr, "Duplicate subject found for \"%s\""
			" in role %s, on line %lu of %s.\n"
			"\"%s\" references the same object as \"%s\""
			" specified on an earlier line.\n"
			"The RBAC system will not load until this"
			" error is fixed.\n", p->filename, 
			role->rolename, lineno,
			current_acl_file, p->filename, p2->filename);
		exit(EXIT_FAILURE);
	}

	/* don't insert nested subjects into main hash */
	if (!(flag & GR_FFAKE))
		insert_acl_subject(role, p);
	else
		insert_nested_acl_subject(p);

	current_subject = p;

	return 1;
}

u_int16_t
role_mode_conv(const char *mode)
{
	int len = strlen(mode) - 1;
	u_int16_t retmode = GR_ROLE_DEFAULT;

	for (; len >= 0; len--) {
		switch (mode[len]) {
		case 'u':
			retmode &= ~GR_ROLE_DEFAULT;
			retmode |= GR_ROLE_USER;
			break;
		case 'g':
			retmode &= ~GR_ROLE_DEFAULT;
			retmode |= GR_ROLE_GROUP;
			break;
		case 's':
			retmode &= ~GR_ROLE_DEFAULT;
			retmode |= GR_ROLE_SPECIAL;
			break;
		case 'l':
			retmode |= GR_ROLE_LEARN;
			break;
		case 'G':
			retmode |= GR_ROLE_AUTH;
			break;
		case 'N':
			retmode |= GR_ROLE_NOPW;
			break;
		case 'A':
			retmode |= GR_ROLE_GOD;
			break;
		case 'R':
			retmode |= GR_ROLE_PERSIST;
			break;
		case 'T':
			retmode |= GR_ROLE_TPE;
			break;
		
		case 'P':
			retmode |= GR_ROLE_PAM;
			break;
		default:
			fprintf(stderr, "Invalid role mode "
				"\'%c\' found on line %lu "
				"of %s\n", mode[len], lineno, current_acl_file);
			exit(EXIT_FAILURE);
		}
	}

	if ((retmode & (GR_ROLE_SPECIAL | GR_ROLE_PERSIST)) == GR_ROLE_PERSIST) {
		fprintf(stderr, "Error on line %lu of %s.  Persistent "
			"roles are only valid in the context of special roles.\n"
			"The RBAC system will not load until this error is fixed.\n", lineno, current_acl_file);
		exit(EXIT_FAILURE);
	}

	if ((retmode & (GR_ROLE_NOPW | GR_ROLE_PAM)) == (GR_ROLE_NOPW | GR_ROLE_PAM)) {
		fprintf(stderr, "Error on line %lu of %s.  The role mode must contain only one of the noauth and pamauth modes.\n", lineno, current_acl_file);
		exit(EXIT_FAILURE);
	}

	if ((retmode & GR_ROLE_SPECIAL) &&
	    (retmode & (GR_ROLE_USER | GR_ROLE_GROUP))) {
		fprintf(stderr, "Error on line %lu of %s.  The role mode must be either "
				"special, or user/group, not both.\n"
				"The RBAC system will not load until this"
				" error is fixed.\n", lineno, current_acl_file); 
		exit(EXIT_FAILURE);
	}

	if ((retmode & (GR_ROLE_USER | GR_ROLE_GROUP)) && (retmode & GR_ROLE_NOPW)) {
		fprintf(stderr, "Error on line %lu of %s.  The role mode \"N\" can only "
				"be used with a special role.\n"
				"The RBAC system will not load until this"
				" error is fixed.\n", lineno, current_acl_file); 
		exit(EXIT_FAILURE);
	}
	if ((retmode & (GR_ROLE_USER | GR_ROLE_GROUP)) ==
		(GR_ROLE_USER | GR_ROLE_GROUP)) {
		fprintf(stderr, "Error on line %lu of %s.  The role mode cannot be both "
				"user or group, you must choose one.\n"
				"The RBAC system will not load until this"
				" error is fixed.\n", lineno, current_acl_file); 
		exit(EXIT_FAILURE);
	}

	return retmode;
}

u_int32_t
proc_subject_mode_conv(const char *mode)
{
	int i;
	u_int32_t retmode = 0;

	retmode |= GR_PROCFIND;

	for (i = 0; i < strlen(mode); i++) {
		switch (mode[i]) {
		case 'T':
			retmode |= GR_NOTROJAN;
			break;
		case 'K':
			retmode |= GR_KILLPROC;
			break;
		case 'C':
			retmode |= GR_KILLIPPROC;
			break;
		case 'A':
			retmode |= GR_PROTSHM;
			break;
		case 'O':
			retmode |= GR_IGNORE;
			break;
		case 'Z':
			retmode |= GR_SUBJ_REPLACE;
			break;
		case 'o':
			retmode |= GR_OVERRIDE;
			break;
		case 't':
			retmode |= GR_POVERRIDE;
			break;
		case 'l':
			retmode |= GR_LEARN;
			break;
		case 'h':
			retmode &= ~GR_PROCFIND;
			break;
		case 'p':
			retmode |= GR_PROTECTED;
			break;
		case 'k':
			retmode |= GR_KILL;
			break;
		case 'v':
			retmode |= GR_VIEW;
			break;
		case 'd':
			retmode |= GR_PROTPROCFD;
			break;
		case 'b':
			retmode |= GR_PROCACCT;
			break;
		case 'r':
			retmode |= GR_RELAXPTRACE;
			break;
		case 'i':
			retmode |= GR_INHERITLEARN;
			break;
		case 'a':
			retmode |= GR_KERNELAUTH;
			break;
		case 's':
			retmode |= GR_ATSECURE;
			break;
		case 'x':
			retmode |= GR_SHMEXEC;
			break;
		default:
			fprintf(stderr, "Invalid subject mode "
				"\'%c\' found on line %lu "
				"of %s\n", mode[i], lineno, current_acl_file);
			exit(EXIT_FAILURE);
		}
	}

	return retmode;
}

u_int32_t
proc_object_mode_conv(const char *mode)
{
	int i;
	u_int32_t retmode = 0;

	retmode |= GR_FIND;

	for (i = 0; i < strlen(mode); i++) {
		switch (mode[i]) {
		case 'r':
			retmode |= GR_READ;
			break;
		case 'w':
			retmode |= GR_WRITE;
			retmode |= GR_APPEND;
			break;
		case 'c':
			retmode |= GR_CREATE;
			break;
		case 'd':
			retmode |= GR_DELETE;
			break;
		case 'x':
			retmode |= GR_EXEC;
			break;
		case 'a':
			retmode |= GR_APPEND;
			break;
		case 'h':
			retmode &= ~GR_FIND;
			break;
		case 'i':
			retmode |= GR_INHERIT;
			break;
		case 't':
			retmode |= GR_PTRACERD;
			break;
		case 'l':
			retmode |= GR_LINK;
			break;
		case 'Z':
			retmode |= GR_OBJ_REPLACE;
			break;
		case 'F':
			retmode |= GR_AUDIT_FIND;
			break;
		case 'R':
			retmode |= GR_AUDIT_READ;
			break;
		case 'W':
			retmode |= GR_AUDIT_WRITE;
			retmode |= GR_AUDIT_APPEND;
			break;
		case 'X':
			retmode |= GR_AUDIT_EXEC;
			break;
		case 'A':
			retmode |= GR_AUDIT_APPEND;
			break;
		case 'I':
			retmode |= GR_AUDIT_INHERIT;
			break;
		case 'M':
			retmode |= GR_AUDIT_SETID;
			break;
		case 'C':
			retmode |= GR_AUDIT_CREATE;
			break;
		case 'D':
			retmode |= GR_AUDIT_DELETE;
			break;
		case 'L':
			retmode |= GR_AUDIT_LINK;
			break;
		case 's':
			retmode |= GR_SUPPRESS;
			break;
		case 'f':
			if (!(current_role->roletype & GR_ROLE_PERSIST)) {
				fprintf(stderr, "Error on line %lu of "
				"%s.  The 'f' mode is only permitted "
				"within persistent special roles.\n"
				"The RBAC system will not be allowed to "
				"be enabled until this error is corrected.\n",
				lineno, current_acl_file);
				exit(EXIT_FAILURE);
			}
			retmode |= GR_INIT_TRANSFER;
			break;
		case 'm':
			retmode |= GR_SETID;
			break;
		case 'p':
			retmode |= GR_NOPTRACE;
			break;
		default:
			fprintf(stderr, "Invalid proc object mode "
				"\'%c\' found on line %lu "
				"of %s\n", mode[i], lineno, current_acl_file);
		}
	}

	return retmode;
}

void
parse_acls(void)
{
	if (chdir(GRSEC_DIR) < 0) {
		fprintf(stderr, "Error changing directory to %s\n"
			"Error: %s\n", GRSEC_DIR, strerror(errno));
		exit(EXIT_FAILURE);
	}

	gradmin = open_acl_file(GR_POLICY_PATH);
	change_current_acl_file(GR_POLICY_PATH);
	gradmparse();

	add_kernel_acl();

	return;
}

static void
setup_special_roles(struct gr_arg *grarg)
{
	struct role_acl *rtmp = NULL;
	struct gr_pw_entry entry;
	int err;
	u_int16_t i = 0;

	memset(&entry, 0, sizeof (struct gr_pw_entry));

	err = mlock(&entry, sizeof (struct gr_pw_entry));
	if (err && !getuid())
		fprintf(stderr, "Warning, unable to lock authentication "
			"structure in physical memory.\n");

	for_each_role(rtmp, current_role) {
		if (rtmp->roletype & GR_ROLE_SPECIAL &&
		    !(rtmp->roletype & (GR_ROLE_NOPW | GR_ROLE_PAM))) {
			strncpy((char *)entry.rolename, rtmp->rolename, GR_SPROLE_LEN);
			entry.rolename[GR_SPROLE_LEN - 1] = '\0';
			if (!read_saltandpass
			    (entry.rolename, entry.salt, entry.sum)) {
				fprintf(stderr,
					"No password exists for special "
					"role %s.\nRun gradm -P %s to set up a password "
					"for the role.\n", rtmp->rolename,
					rtmp->rolename);
				exit(EXIT_FAILURE);
			}
			grarg->sprole_pws[i].rolename =
			    (const unsigned char *) rtmp->rolename;
			memcpy(grarg->sprole_pws[i].salt, entry.salt,
			       GR_SALT_SIZE);
			memcpy(grarg->sprole_pws[i].sum, entry.sum,
			       GR_SHA_SUM_SIZE);
			memset(&entry, 0, sizeof (struct gr_pw_entry));
			i++;
		}
	}

	return;
}

struct gr_arg_wrapper *
conv_user_to_kernel(struct gr_pw_entry *entry)
{
	struct gr_arg_wrapper *wrapper;
	struct gr_arg *retarg;
	struct user_acl_role_db *role_db;
	struct role_acl *rtmp = NULL;
	struct role_acl **r_tmp = NULL;
	unsigned long racls = 0;
	u_int16_t sproles = 0;
	int err;

	for_each_role(rtmp, current_role) {
		racls++;
		if (rtmp->roletype & GR_ROLE_SPECIAL &&
		    !(rtmp->roletype & (GR_ROLE_NOPW | GR_ROLE_PAM)))
			sproles++;
	}

	retarg = (struct gr_arg *) gr_alloc(sizeof (struct gr_arg));
	wrapper = (struct gr_arg_wrapper *) gr_alloc(sizeof (struct gr_arg_wrapper));

	wrapper->version = GRADM_VERSION;
	wrapper->size = sizeof(struct gr_arg);
	wrapper->arg = retarg;

	err = mlock(retarg, sizeof (struct gr_arg));
	if (err && !getuid())
		fprintf(stderr, "Warning, unable to lock authentication "
			"structure in physical memory.\n");

	if (!racls)	// we are disabling, don't want to calloc 0
		goto set_pw;

	retarg->sprole_pws = (struct sprole_pw *) gr_alloc(sproles * sizeof (struct sprole_pw));

	err = mlock(retarg->sprole_pws, sproles * sizeof (struct sprole_pw));
	if (err && !getuid())
		fprintf(stderr, "Warning, unable to lock authentication "
			"structure in physical memory.\n");

	setup_special_roles(retarg);

	retarg->num_sprole_pws = sproles;

	role_db = (struct user_acl_role_db *) gr_alloc(sizeof (struct user_acl_role_db));

	role_db->num_pointers = num_pointers;
	role_db->num_roles = num_roles;
	role_db->num_domain_children = num_domain_children;
	role_db->num_subjects = num_subjects;
	role_db->num_objects = num_objects;

	if (racls >= ULONG_MAX/sizeof(struct role_acl *)) {
		fprintf(stderr, "Too many roles.\n");
		exit(EXIT_FAILURE);
	}

	r_tmp = role_db->r_table = (struct role_acl **) gr_alloc(racls * sizeof (struct role_acl *));

	for_each_role(rtmp, current_role) {
		if (!(rtmp->roletype & GR_ROLE_IGNORENOEXIST)) {
			*r_tmp = rtmp;
			r_tmp++;
		}
	}

	memcpy(&retarg->role_db, role_db, sizeof (struct user_acl_role_db));
      set_pw:

	strncpy((char *)retarg->pw, (char *)entry->passwd, GR_PW_LEN - 1);
	retarg->pw[GR_PW_LEN - 1] = '\0';
	strncpy((char *)retarg->sp_role, (char *)entry->rolename, GR_SPROLE_LEN);
	retarg->sp_role[GR_SPROLE_LEN - 1] = '\0';

	retarg->mode = entry->mode;
	retarg->segv_inode = entry->segv_inode;
	retarg->segv_dev = entry->segv_dev;
	retarg->segv_uid = entry->segv_uid;

	memset(entry, 0, sizeof (struct gr_pw_entry));

	return wrapper;
}
