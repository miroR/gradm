/*
 * Copyright (C) 2002-2016 Bradley Spengler, Open Source Security, Inc.
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

struct file_acl *get_exact_matching_object(struct proc_acl *subject, const char *filename)
{
	struct file_acl *tmpf = NULL;
	struct proc_acl *tmpp = subject;
	struct file_acl *tmpg = NULL;
	char *tmpname = (char *)alloca(strlen(filename) + 1);
	int reduced_dir = 0;
	strcpy(tmpname, filename);

	do {
		tmpp = subject;
		do {
			tmpf = lookup_acl_object_by_name(tmpp, tmpname);
			if (!tmpf)
				tmpf = lookup_acl_object_by_inodev_nofollow(tmpp, tmpname);
			if (tmpf) {
				/* check globbed objects */
				for_each_globbed(tmpg, tmpf) {
					if (!fnmatch(tmpg->filename, filename, 0))
						return tmpg;
				}
				if (!reduced_dir)
					return tmpf;
			}
		} while ((tmpp = tmpp->parent_subject));
		reduced_dir = 1;
	} while (parent_dir(filename, &tmpname));

	// won't get here
	return NULL;
}

static struct file_acl *get_a_matching_object(struct proc_acl *subject, 
				const char *filename, const char *origname, int follow)
{
	struct file_acl *tmpf, *tmpg;
	struct proc_acl *tmpp = subject;
	do {
		tmpf = lookup_acl_object_by_name(tmpp, filename);
		if (!tmpf) {
			if (follow)
				tmpf = lookup_acl_object_by_inodev(tmpp, filename);
			else
				tmpf = lookup_acl_object_by_inodev_nofollow(tmpp, filename);
		}
		if (tmpf) {
			/* check globbed objects */
			for_each_globbed(tmpg, tmpf) {
				if (!fnmatch(tmpg->filename, origname, 0))
					return tmpg;
			}
			return tmpf;
		}
	} while ((tmpp = tmpp->parent_subject));

	return NULL;
}

static struct file_acl *__get_matching_object(struct proc_acl *subject, const char *filename, int follow)
{
	struct file_acl *tmpf = NULL;
	char *tmpname = (char *)alloca(strlen(filename) + 1);

	strcpy(tmpname, filename);

	do {
		tmpf = get_a_matching_object(subject, tmpname, filename, follow);
		if (tmpf)
			return tmpf;
	} while (parent_dir(filename, &tmpname));

	// won't get here
	return NULL;
}

struct file_acl *get_matching_object(struct proc_acl *subject, const char *filename)
{
	return __get_matching_object(subject, filename, 1);
}

struct file_acl *get_matching_object_nofollow(struct proc_acl *subject, const char *filename)
{
	return __get_matching_object(subject, filename, 0);
}

static int
check_permission(struct role_acl *role, struct proc_acl *def_acl,
		 const char *filename, struct chk_perm *chk)
{
	struct file_acl *tmpf = NULL;
	struct proc_acl *tmpp = def_acl;
	gr_cap_t cap_drp = {{ 0, 0 }}, cap_mask = {{ 0, 0 }};
	gr_cap_t cap_full = {{ ~0, ~0 }};

	if (chk->type == CHK_FILE) {
		tmpf = get_matching_object(def_acl, filename);
		if (((chk->w_modes == 0xffff)
		     || (tmpf->mode & chk->w_modes))
		     && ((chk->u_modes == 0xffff)
		     || !(tmpf->mode & chk->u_modes))) {
			return 1;
		} else {
			return 0;
		}
	} else if (chk->type == CHK_CAP) {
		cap_mask = tmpp->cap_mask;
		cap_drp = tmpp->cap_drop;

		while ((tmpp = tmpp->parent_subject)) {
			cap_drp = cap_combine(cap_drp, cap_intersect(tmpp->cap_drop,
								       cap_drop(tmpp->cap_mask, cap_mask)));
			cap_mask = cap_combine(cap_mask, tmpp->cap_mask);
		}

		if (((cap_same(chk->w_caps, cap_full))
		     || cap_isclear(cap_intersect(cap_drp, chk->w_caps)))
		    && ((cap_same(chk->u_caps, cap_full))
			|| !cap_isclear(cap_intersect(cap_drp, chk->u_caps))))
			return 1;
	}

	return 0;
}

static unsigned int
insert_globbed_objects(void)
{
	struct glob_file *glob;
	struct glob_file *tmp;
	struct glob_file *subj_start = glob_files_head;
	unsigned int num_errors = 0;

	for (glob = glob_files_head; glob; glob = glob->next) {
		/* check previous globbed objects for this subject, looking for one that completely matches this later object */
		if (subj_start->subj != glob->subj)
			subj_start = glob;
		for (tmp = subj_start; tmp && tmp != glob; tmp = tmp->next) {
			/* doesn't cover all cases, but covers enough */
			if (!anchorcmp(tmp->filename, glob->filename) && !fnmatch(tmp->filename, glob->filename, 0)) {
				fprintf(stderr, "Error on line %lu of %s: Globbed object %s in subject %s is completely matched by previous "
						"globbed object %s.  As globbed objects with the same anchor are matched on a "
						"first-rule-matches-first policy, the ordering present in your policy likely does not reflect "
						"your intentions.\r\n",
					glob->lineno, glob->policy_file, glob->filename, glob->subj->filename, tmp->filename);
				num_errors++;
			}
		}
		add_globbed_object_acl(glob->subj, glob->filename, glob->mode, glob->type, glob->policy_file, glob->lineno);
	}

	return num_errors;
}

static void
check_symlinks(void)
{
	struct symlink *sym;
	struct file_acl *tmpf;

	for (sym = symlinks; sym; sym = sym->next) {
		char buf[PATH_MAX];
		struct stat64 src_st, dst_st;
		memset(&buf, 0, sizeof (buf));

		if (!realpath(sym->obj->filename, buf))
			continue;

		/* warning exemptions */
		if (!strcmp(buf, "/proc/self"))
			continue;

		tmpf = get_matching_object(sym->subj, buf);
		if (tmpf->mode != sym->obj->mode) {
			fprintf(stdout, "Warning: permission for symlink %s in role %s, subject %s does not match that of its matching target object %s.  Symlink is specified on line %lu of %s.\n",
				sym->obj->filename, sym->role->rolename, sym->subj->filename, tmpf->filename, sym->lineno, sym->policy_file);
		}
		else if (!lstat64(buf, &dst_st) && !lstat64(sym->obj->filename, &src_st) && src_st.st_uid != dst_st.st_uid) {
			fprintf(stdout, "Warning: owner of symlink %s in role %s, subject %s does not match that of its target %s.  Symlink is specified on line %lu of %s.\n",
				sym->obj->filename, sym->role->rolename, sym->subj->filename, buf, sym->lineno, sym->policy_file);
		}
	}

	return;
}

static int
check_subjects(struct role_acl *role)
{
	struct proc_acl *tmp;
	struct proc_acl *def_acl;
	struct chk_perm chk;
	unsigned int errs_found = 0;

	chk.type = CHK_FILE;
	chk.u_modes = GR_WRITE;
	chk.w_modes = 0xffff;

	def_acl = role->root_label;
	if (!def_acl)
		return 0;

	for_each_subject(tmp, role)
	    if ((tmp->filename[0] == '/') && (tmp->filename[1] != '\0'))
		if (!check_permission(role, def_acl, tmp->filename, &chk))
			fprintf(stderr,
				"Warning: write access is allowed to your "
				"subject for %s in role %s.  Please ensure that the subject is running with less privilege than the default subject.\n",
				tmp->filename, role->rolename);

	return errs_found;
}

static int
check_learning(struct role_acl *role)
{
	struct proc_acl *tmp;
	struct proc_acl *def_acl;
	unsigned int errs_found = 0;

	def_acl = role->root_label;
	if (!def_acl)
		return 0;
	if (gr_learn)
		return 0;

	if (!gr_learn && role->roletype & GR_ROLE_LEARN) {
		fprintf(stderr,
			"Error: You have enabled learning on the role "
			"%s.  You have not used -L on the command "
			"line however.  If you wish to use learning "
			"on this role, use the -L argument to gradm.  "
			"Otherwise, remove the learning flag on this role.\n",
			role->rolename);
		errs_found++;
	}

	for_each_subject(tmp, role) {
	    if (!gr_learn && (tmp->mode & (GR_LEARN | GR_INHERITLEARN))) {
			fprintf(stderr,
				"Error: You have enabled some form of "
				"learning on the subject for %s in role "
				"%s.  You have not used -L on the command "
				"line however.  If you wish to use learning "
				"on this subject, use the -L argument to gradm.  "
				"Otherwise, remove the learning flag on this subject.\n",
				tmp->filename, role->rolename);
		errs_found++;
	    }
	}

	return errs_found;
}

static void
check_default_objects(struct role_acl *role)
{
	struct proc_acl *tmp;
	struct file_acl *tmpf;

	for_each_subject(tmp, role) {
		/* skip all inherited subjects */
		if (tmp->parent_subject != NULL)
			continue;
		tmpf = lookup_acl_object_by_name(tmp, "/");
		if (tmpf == NULL) {
			fprintf(stderr, "Default object not found for "
				"role %s subject %s\nThe RBAC system will "
				"not load until you correct this "
				"error.\n", role->rolename, tmp->filename);
			exit(EXIT_FAILURE);
		}
	}

	return;
}

static unsigned int
check_nested_default_objects(void)
{
	struct proc_acl *tmp;
	struct file_acl *tmpf;
	unsigned int errs_found = 0;

	for_each_nested_subject(tmp) {
		/* skip all inherited subjects */
		if (tmp->parent_subject != NULL)
			continue;
		tmpf = lookup_acl_object_by_name(tmp, "/");
		if (tmpf == NULL) {
			fprintf(stderr, "Default object not found for "
				"nested subject %s\n", tmp->filename);
			errs_found++;
		}
	}

	return errs_found;
}

static void
check_subject_modes(struct role_acl *role)
{
	struct proc_acl *tmp;

	for_each_subject(tmp, role) {
		if ((tmp->mode & GR_LEARN) && (tmp->mode & GR_INHERITLEARN)) {
			fprintf(stderr, "Invalid subject mode found for "
				"role %s subject %s\nBoth \"i\" and \"l\" modes "
				"cannot be used together.  Please choose either "
				"normal or inheritance-based learning for the "
				"subject.\nThe RBAC system will not load until you "
				"correct this error.\n", role->rolename, tmp->filename);
			exit(EXIT_FAILURE);
		}
	}

	return;
}

static int get_symlinked_dir(const char *filename, char *out, char *target)
{
	char *p = out;
	struct stat64 st;

	strncpy(out, filename, PATH_MAX);
	out[PATH_MAX-1] = '\0';
	p = strchr(p + 1, '/');
	while (p) {
		*p = '\0';
		if (lstat64(out, &st))
			break;
		if (S_ISLNK(st.st_mode)) {
			realpath(out, target);
			return 1;
		}
		*p = '/';
		p = strchr(p + 1, '/');
	}

	return 0;
}

static void
check_noncanonical_paths(struct role_acl *role)
{
	struct proc_acl *subj;
	struct file_acl *obj;
	struct file_acl *targobj, *targobj2;
	struct stat64 st1, st2;
	char tmp[PATH_MAX];
	char tmp2[PATH_MAX];

	for_each_subject(subj, role) {
		for_each_file_object(obj, subj) {
			if (get_symlinked_dir(obj->filename, (char *)tmp, (char *)tmp2)) {
				targobj = get_matching_object_nofollow(subj, tmp);
				if (targobj->mode & GR_WRITE) {
					fprintf(stderr, "Warning: In role %s subject %s, pathname \"%s\":\nA writable and symlinked directory \"%s\" points to \"%s\".\n",
						role->rolename, subj->filename, obj->filename, tmp, tmp2);
				}
			}
		}
	}
	return;
}

static void
check_socket_policies(struct role_acl *role)
{
	struct proc_acl *tmp;
	struct ip_acl *tmpi;
	int has_connect;
	int has_bind;
	unsigned int i;

	for_each_subject(tmp, role) {
		has_connect = 0;
		has_bind = 0;
		for (i = 0; i < tmp->ip_num; i++) {
			tmpi = tmp->ips[i];
			if (tmpi->mode & GR_IP_BIND)
				has_bind = 1;
			if (tmpi->mode & GR_IP_CONNECT)
				has_connect = 1;
		}
		/* if we have either a bind or a connect, but not either
		   and not both */
		if (has_bind ^ has_connect) {
			fprintf(stderr, "A %s rule exists but a %s rule is missing for "
				"role %s subject %s\nThe RBAC system will "
				"not load until you correct this "
				"error.\n", has_connect ? "connect" : "bind",
				has_bind ? "connect" : "bind",  
				role->rolename, tmp->filename);
			exit(EXIT_FAILURE);
		}
		if (tmp->parent_subject && tmp->parent_subject->ips && !tmp->ips)
			fprintf(stderr, "Warning: Network policies do not support policy inheritance.  Please inspect policy for subject %s in role %s to make sure you intended to allow all network activity.\n", tmp->filename, role->rolename);

	}

	return;
}

static int
check_lilo_conf(struct role_acl *role, struct proc_acl *def_acl)
{
	FILE *liloconf;
	char buf[PATH_MAX];
	struct stat fstat;
	struct chk_perm chk;
	unsigned int errs_found = 0;
	char *p;

	if ((liloconf = fopen("/etc/lilo.conf", "r")) == NULL)
		return 0;

	chk.type = CHK_FILE;
	chk.u_modes = GR_WRITE;
	chk.w_modes = 0xffff;

	while (fgets(buf, PATH_MAX - 1, liloconf)) {
		if (buf[strlen(buf) - 1] == '\n')
			buf[strlen(buf) - 1] = '\0';
		if ((p = strstr(buf, "image="))) {
			p += 6;
			if (!stat(p, &fstat)
			    && !check_permission(role, def_acl, p, &chk)) {
				fprintf(stderr,
					"Write access is allowed by role %s to %s, a kernel "
					"for your system specified in "
					"/etc/lilo.conf.\n\n", role->rolename,
					p);
				errs_found++;
			}
		}
	}

	fclose(liloconf);

	return errs_found;
}

static int
check_lib_paths(struct role_acl *role, struct proc_acl *def_acl)
{
	FILE *ldconf;
	char buf[PATH_MAX];
	struct stat fstat;
	struct chk_perm chk;
	unsigned int errs_found = 0;

	if ((ldconf = fopen("/etc/ld.so.conf", "r")) == NULL)
		return 0;

	chk.type = CHK_FILE;
	chk.u_modes = GR_WRITE;
	chk.w_modes = 0xffff;

	while (fgets(buf, PATH_MAX - 1, ldconf)) {
		if (buf[strlen(buf) - 1] == '\n')
			buf[strlen(buf) - 1] = '\0';

		if (!stat(buf, &fstat)
		    && !check_permission(role, def_acl, buf, &chk)) {
			fprintf(stderr,
				"Write access is allowed by role %s to %s, a directory which "
				"holds libraries for your system and is included "
				"in /etc/ld.so.conf.\n\n", role->rolename, buf);
			errs_found++;
		}
	}

	fclose(ldconf);

	return errs_found;
}

static int
check_path_env(struct role_acl *role, struct proc_acl *def_acl)
{
	char *pathstr, *p, *p2;
	char pathbuf[PATH_MAX];
	struct stat fstat;
	struct chk_perm chk;
	unsigned int errs_found = 0;

	if ((pathstr = getenv("PATH")) == NULL)
		return 0;

	p = pathstr;

	chk.type = CHK_FILE;
	chk.u_modes = GR_WRITE;
	chk.w_modes = 0xffff;

	while ((p2 = strchr(p, ':'))) {
		*p2++ = '\0';
		memset(pathbuf, 0, sizeof(pathbuf));
		if (!realpath(p, pathbuf))
			goto next;
		if (!stat(pathbuf, &fstat)
		    && !check_permission(role, def_acl, pathbuf, &chk)) {
			fprintf(stderr,
				"Write access is allowed by role %s to %s, a directory which "
				"holds binaries for your system and is included "
				"in the PATH environment variable.\n\n",
				role->rolename, pathbuf);
			errs_found++;
		}
next:
		p = p2;
	}

	memset(pathbuf, 0, sizeof(pathbuf));
	if (!realpath(p, pathbuf))
		goto reterr;

	if (!stat(pathbuf, &fstat) && !check_permission(role, def_acl, pathbuf, &chk)) {
		fprintf(stderr,
			"Write access is allowed by role %s to %s, a directory which "
			"holds binaries for your system and is included "
			"in the PATH environment variable.\n\n", role->rolename,
			pathbuf);
		errs_found++;
	}

reterr:
	return errs_found;
}

static int
handle_notrojan_mode(void)
{
	struct proc_acl *subj, *subj2;
	struct file_acl *obj, *obj2;
	struct role_acl *role, *role2;
	char *objname;
	int ret = 0;

	for_each_role(role, current_role) {
		if (!strcmp(role->rolename, ":::kernel:::"))
			continue;
		for_each_subject(subj, role) {
			if (!(subj->mode & GR_NOTROJAN))
				continue;
			for_each_file_object(obj, subj) {
				if (!(obj->mode & GR_EXEC))
					continue;
				for_each_role(role2, current_role) {
					if (!strcmp(role2->rolename, ":::kernel:::"))
						continue;
					if (role2->roletype & GR_ROLE_GOD)
						continue;
					for_each_subject(subj2, role2) {
						if (subj2 == subj
						    || (subj2->
							filename[0] !=
							'/'))
							continue;
						objname = gr_strdup(obj->filename);
						do {
							obj2 = lookup_acl_object_by_name(subj2, objname);
							if (obj2 && obj2->mode & GR_WRITE) {
								ret++;
								fprintf(stderr,
								     "\'T\' specified in mode for role %s, subject %s.\n"
								     "%s's executable object %s is "
								     "writable by role %s, subject %s, due to its "
								     "writable object %s.\nThis would "
								     "allow %s to execute trojaned code.\n\n",
								     role->rolename, subj->filename,
								     subj->filename, obj->filename,
								     role2->rolename, subj2->filename,
								     obj2->filename, subj->filename);
								break;
							} else if (obj2) {
								/* if we found a match, but it wasn't writable, then just break
								   otherwise we'd end up matching on a directory whose
								   mode doesn't apply to what we're looking up
								*/
								break;
							}
						} while (parent_dir(obj->filename, &objname));
						free(objname);
					}
				}
			}
		}
	}

	return ret;
}

int
check_role_transitions(void)
{
	struct role_acl *role, *role2;
	struct role_transition *trans;
	int num_sproles = 0;
	int found = 0;
	int i;
	int errors = 0;
	struct role_acl **sprole_table;

	for_each_role(role, current_role) {
		if (role->roletype & GR_ROLE_SPECIAL)
			num_sproles++;
	}
	sprole_table = (struct role_acl **)malloc(num_sproles * sizeof(struct role_acl *));
	if (sprole_table == NULL)
		failure("malloc");

	i = 0;
	for_each_role(role, current_role) {
		if (role->roletype & GR_ROLE_SPECIAL) {
			sprole_table[i] = role;
			i++;
		}
	}

	for_each_role(role, current_role) {
		if (role->transitions && !(role->roletype & (GR_ROLE_SPECIAL | GR_ROLE_AUTH))) {
			fprintf(stderr, "Error in role %s: a transition to a special role exists, "
					"but the \"G\" flag is not present on the role to grant it "
					"permission to use gradm to change to the special role.\n",
					role->rolename);
			errors++;
		}
		for_each_transition(trans, role->transitions) {
			found = 0;
			for_each_role(role2, current_role) {
				if (!(role2->roletype & GR_ROLE_SPECIAL))
					continue;
				if (!strcmp(role2->rolename, trans->rolename)) {
					found = 1;
					for(i = 0; i < num_sproles; i++) {
						if (sprole_table[i] == role2) {
							sprole_table[i] = NULL;
							break;
						}
					}
				}
			}
			if (!found) {
				fprintf(stderr,
					"Error in transition to special role %s in role "
					"%s.\nSpecial role %s does not exist.\n",
					trans->rolename, role->rolename,
					trans->rolename);
				errors++;
			}
		}
	}

	for (i = 0; i < num_sproles; i++) {
		if (sprole_table[i] != NULL) {
			fprintf(stderr,
				"Special role %s is not accessible from any role.  Make sure "
				"you have a role_transitions line added in all roles that will "
				"access the special role.\n", sprole_table[i]->rolename);
			errors++;
		}
	}
	free(sprole_table);

	return errors;
}

void
analyze_acls(void)
{
	struct proc_acl *def_acl;
	struct chk_perm chk;
	unsigned int errs_found = 0;
	struct role_acl *role;
	int def_role_found = 0;
	struct stat fstat;
	gr_cap_t cap_full = {{ ~0, ~0 }};

	errs_found += insert_globbed_objects();

	errs_found += check_role_transitions();

	errs_found += check_nested_default_objects();

	for_each_role(role, current_role)
		if (role->roletype & GR_ROLE_DEFAULT)
			def_role_found = 1;

	if (!def_role_found) {
		fprintf(stderr, "There is no default role present in your "
			"configuration.\nPlease read the RBAC "
			"documentation and create a default role before "
			"attempting to enable the RBAC system.\n\n");
		exit(EXIT_FAILURE);
	}

	for_each_role(role, current_role) {
		if (((role->roletype & (GR_ROLE_GOD | GR_ROLE_PERSIST)) == 
		     (GR_ROLE_GOD | GR_ROLE_PERSIST)) &&
		    !strcmp(role->rolename, "admin")) {
			fprintf(stderr, "The admin role has been marked "
			"as a persistent role.  This severely compromises "
			"security as any process restarted via an admin "
			"role will retain the admin role indefinitely.\n"
			"Please create a specific role for the handling "
			"of system shutdown (the common use case of "
			"persistent special roles).  The RBAC system will "
			"not be allowed to be enabled until this error is "
			"fixed.\n");
			exit(EXIT_FAILURE);
		}

		def_acl = role->root_label;
		if (!def_acl) {
			fprintf(stderr, "There is no default subject for "
				"the role for %s present in your "
				"configuration.\nPlease read the RBAC "
				"documentation and create a default subject "
				"before attempting to enable the RBAC "
				"system.\n", role->rolename);
			exit(EXIT_FAILURE);
		}

		check_default_objects(role);
		check_subject_modes(role);
		check_socket_policies(role);

		check_noncanonical_paths(role);

		/* non-critical warnings aren't issued for special roles */
		if (role->roletype & GR_ROLE_SPECIAL)
			continue;

		errs_found += check_subjects(role);
		errs_found += check_learning(role);

		chk.type = CHK_FILE;
		chk.u_modes = GR_FIND;
		chk.w_modes = 0xffff;

		if (!check_permission(role, def_acl, GRDEV_PATH, &chk)) {
			fprintf(stderr,
				"Viewing access is allowed by role %s to %s.\n"
				"If you want this role to be able to authenticate to the kernel, add G to its role mode.\n\n",
				role->rolename, GRDEV_PATH);
			errs_found++;
		}

		if (!check_permission(role, def_acl, GRSEC_DIR, &chk)) {
			fprintf(stderr,
				"Viewing access is allowed by role %s to %s, the directory which "
				"stores RBAC policies and RBAC password information.\n\n",
				role->rolename, GRSEC_DIR);
			errs_found++;
		}

		if (!check_permission(role, def_acl, "/dev/kmem", &chk)) {
			fprintf(stderr,
				"Viewing access is allowed by role %s to /dev/kmem.  This could "
				"allow an attacker to modify the code of your "
				"running kernel.\n\n", role->rolename);
			errs_found++;
		}

		if (!check_permission(role, def_acl, "/dev/mem", &chk)) {
			fprintf(stderr,
				"Viewing access is allowed by role %s to /dev/mem.  This would "
				"allow an attacker to modify the code of programs "
				"running on your system.\n\n", role->rolename);
			errs_found++;
		}

		if (!check_permission(role, def_acl, "/dev/port", &chk)) {
			fprintf(stderr,
				"Viewing access is allowed by role %s to /dev/port.  This would "
				"allow an attacker to modify the code of programs "
				"running on your system.\n\n", role->rolename);
			errs_found++;
		}

		if (!stat("/proc/kcore", &fstat) && !check_permission(role, def_acl, "/proc/kcore", &chk)) {
			fprintf(stderr,
				"Viewing access is allowed by role %s to /proc/kcore.  This would "
				"allow an attacker to view the raw memory of processes "
				"running on your system.\n\n", role->rolename);
			errs_found++;
		}

		chk.u_modes = GR_WRITE;

		if (!check_permission(role, def_acl, "/boot", &chk)) {
			fprintf(stderr,
				"Writing access is allowed by role %s to /boot, the directory which "
				"holds boot and kernel information.\n\n",
				role->rolename);
			errs_found++;
		}

		if (!check_permission(role, def_acl, "/run", &chk)) {
			fprintf(stderr,
				"Writing access is allowed by role %s to /run, the directory which "
				"holds information for running services and potentially the initctl device.\n\n",
				role->rolename);
			errs_found++;
		}

		if (!stat("/lib/modules", &fstat) && !check_permission(role, def_acl, "/lib/modules", &chk)) {
			fprintf(stderr,
				"Writing access is allowed by role %s to /lib/modules, the directory which "
				"holds kernel modules.\n\n",
				role->rolename);
			errs_found++;
		}

		if (!stat("/lib64/modules", &fstat) && !check_permission(role, def_acl, "/lib64/modules", &chk)) {
			fprintf(stderr,
				"Writing access is allowed by role %s to /lib64/modules, the directory which "
				"holds kernel modules.\n\n",
				role->rolename);
			errs_found++;
		}

		if (!check_permission(role, def_acl, "/dev", &chk)) {
			fprintf(stderr,
				"Writing access is allowed by role %s to /dev, the directory which "
				"holds system devices.\n\n", role->rolename);
			errs_found++;
		}

		if (!check_permission(role, def_acl, "/dev/log", &chk)) {
			fprintf(stderr,
				"Writing access is allowed by role %s to /dev/log.  This could in some cases allow an attacker"
				" to spoof syslog warnings on your system.\n\n",
				role->rolename);
			errs_found++;
		}

		if (!check_permission(role, def_acl, "/dev/grsec", &chk)) {
			fprintf(stderr,
				"Writing access is allowed by role %s to /dev/grsec.  This could allow an attacker to bypass the PAM authentication feature of the RBAC system.\n\n", role->rolename);
			errs_found++;
		}

		if (!check_permission(role, def_acl, "/root", &chk)) {
			fprintf(stderr,
				"Writing access is allowed by role %s to /root, the directory which "
				"holds shell configurations for the root user.  "
				"If writing is allowed to this directory, an attacker "
				"could modify your $PATH environment to fool you "
				"into executing a trojaned gradm.\n\n",
				role->rolename);
			errs_found++;
		}

		if (!check_permission(role, def_acl, "/proc/sys", &chk)) {
			fprintf(stderr,
				"Write access is allowed by role %s to /proc/sys, the directory which "
				"holds entries that allow modifying kernel variables.\n\n",
				role->rolename);
			errs_found++;
		}

		if (!stat("/sys", &fstat) && !check_permission(role, def_acl, "/sys", &chk)) {
			fprintf(stderr,
				"Write access is allowed by role %s to /sys, the directory which "
				"holds entries that allow modifying kernel variables.\n\n",
				role->rolename);
			errs_found++;
		}

		if (!check_permission(role, def_acl, "/etc", &chk)) {
			fprintf(stderr,
				"Write access is allowed by role %s to /etc, the directory which "
				"holds initialization scripts and configuration files.\n\n",
				role->rolename);
			errs_found++;
		}

		if (!check_permission(role, def_acl, "/lib", &chk)) {
			fprintf(stderr,
				"Write access is allowed by role %s to /lib, a directory which "
				"holds system libraries and loadable modules.\n\n",
				role->rolename);
			errs_found++;
		}

		if (!check_permission(role, def_acl, "/usr/lib", &chk)) {
			fprintf(stderr,
				"Write access is allowed by role %s to /usr/lib, a directory which "
				"holds system libraries.\n\n", role->rolename);
			errs_found++;
		}

		if (!stat("/lib32", &fstat) && !check_permission(role, def_acl, "/lib32", &chk)) {
			fprintf(stderr,
				"Write access is allowed by role %s to /lib32, a directory which "
				"holds system libraries.\n\n",
				role->rolename);
			errs_found++;
		}

		if (!stat("/libx32", &fstat) && !check_permission(role, def_acl, "/libx32", &chk)) {
			fprintf(stderr,
				"Write access is allowed by role %s to /libx32, a directory which "
				"holds system libraries.\n\n",
				role->rolename);
			errs_found++;
		}

		if (!stat("/usr/lib32", &fstat) && !check_permission(role, def_acl, "/usr/lib32", &chk)) {
			fprintf(stderr,
				"Write access is allowed by role %s to /usr/lib32, a directory which "
				"holds system libraries.\n\n", role->rolename);
			errs_found++;
		}

		if (!stat("/usr/libx32", &fstat) && !check_permission(role, def_acl, "/usr/libx32", &chk)) {
			fprintf(stderr,
				"Write access is allowed by role %s to /usr/libx32, a directory which "
				"holds system libraries.\n\n", role->rolename);
			errs_found++;
		}


		if (!stat("/lib64", &fstat) && !check_permission(role, def_acl, "/lib64", &chk)) {
			fprintf(stderr,
				"Write access is allowed by role %s to /lib64, a directory which "
				"holds system libraries.\n\n",
				role->rolename);
			errs_found++;
		}

		if (!stat("/usr/lib64", &fstat) && !check_permission(role, def_acl, "/usr/lib64", &chk)) {
			fprintf(stderr,
				"Write access is allowed by role %s to /usr/lib64, a directory which "
				"holds system libraries.\n\n", role->rolename);
			errs_found++;
		}

		chk.u_modes = GR_READ;

		if (!check_permission(role, def_acl, "/dev", &chk)) {
			fprintf(stderr,
				"Reading access is allowed by role %s to /dev, the directory which "
				"holds system devices.\n\n", role->rolename);
			errs_found++;
		}

		if (!stat("/sys", &fstat) && !check_permission(role, def_acl, "/sys", &chk)) {
			fprintf(stderr,
				"Read access is allowed by role %s to /sys, the directory which "
				"holds entries that often leak information from the kernel.\n\n",
				role->rolename);
			errs_found++;
		}

		if (!stat("/proc/slabinfo", &fstat) && !check_permission(role, def_acl, "/proc/slabinfo", &chk)) {
			fprintf(stderr,
				"Reading access is allowed by role %s to "
				"/proc/slabinfo, an entry that provides "
				"useful information to an attacker "
				"for reliable heap exploitation in the "
				"kernel.\n\n", role->rolename);
			errs_found++;
		}

		if (!stat("/proc/modules", &fstat) && !check_permission(role, def_acl, "/proc/modules", &chk)) {
			fprintf(stderr,
				"Reading access is allowed by role %s to "
				"/proc/modules, an entry that provides "
				"useful kernel addresses to an attacker "
				"for reliable exploitation of the "
				"kernel.\n\n", role->rolename);
			errs_found++;
		}

		if (!check_permission(role, def_acl, "/boot", &chk)) {
			fprintf(stderr,
				"Reading access is allowed by role %s to "
				"/boot, the directory which holds kernel "
				"images.  The ability to read these "
				"images provides an attacker with very "
				"useful information for launching \"ret-to-libc\" "
				"style attacks against the kernel"
				".\n\n", role->rolename);
			errs_found++;
		}

		if (!stat("/lib/modules", &fstat) && !check_permission(role, def_acl, "/lib/modules", &chk)) {
			fprintf(stderr,
				"Reading access is allowed by role %s to "
				"/lib/modules, the directory which holds kernel "
				"kernel modules.  The ability to read these "
				"images provides an attacker with very "
				"useful information for launching \"ret-to-libc\" "
				"style attacks against the kernel"
				".\n\n", role->rolename);
			errs_found++;
		}

		if (!stat("/lib32/modules", &fstat) && !check_permission(role, def_acl, "/lib32/modules", &chk)) {
			fprintf(stderr,
				"Reading access is allowed by role %s to "
				"/lib32/modules, the directory which holds kernel "
				"kernel modules.  The ability to read these "
				"images provides an attacker with very "
				"useful information for launching \"ret-to-libc\" "
				"style attacks against the kernel"
				".\n\n", role->rolename);
			errs_found++;
		}

		if (!stat("/lib64/modules", &fstat) && !check_permission(role, def_acl, "/lib64/modules", &chk)) {
			fprintf(stderr,
				"Reading access is allowed by role %s to "
				"/lib64/modules, the directory which holds kernel "
				"kernel modules.  The ability to read these "
				"images provides an attacker with very "
				"useful information for launching \"ret-to-libc\" "
				"style attacks against the kernel"
				".\n\n", role->rolename);
			errs_found++;
		}

		if (!stat("/proc/kallsyms", &fstat) && !check_permission(role, def_acl, "/proc/kallsyms", &chk)) {
			fprintf(stderr,
				"Reading access is allowed by role %s to "
				"/proc/kallsyms, a pseudo-file that "
				"holds a mapping between kernel "
				"addresses and symbols.  This information "
				"is very useful to an attacker in "
				"sophisticated kernel exploits.\n\n",
				role->rolename);
			errs_found++;
		}

		chk.type = CHK_CAP;
		chk.u_caps = cap_combine(cap_combine(cap_conv("CAP_SYS_MODULE"), cap_conv("CAP_SYS_RAWIO")), 
					 cap_conv("CAP_MKNOD"));
		chk.w_caps = cap_full;

		if (!check_permission(role, def_acl, "", &chk)) {
			fprintf(stderr,
				"CAP_SYS_MODULE, CAP_SYS_RAWIO, and CAP_MKNOD are all not "
				"removed in role %s.  This would allow an "
				"attacker to modify the kernel by means of a "
				"module or corrupt devices on your system.\n\n",
				role->rolename);
			errs_found++;
		}

		chk.u_caps = cap_conv("CAP_SYS_ADMIN");
		chk.w_caps = cap_full;

		if (!check_permission(role, def_acl, "", &chk)) {
			fprintf(stderr, "CAP_SYS_ADMIN is not "
				"removed in role %s.  This would allow an "
				"attacker to mount filesystems to bypass your policies\n\n",
				role->rolename);
			errs_found++;
		}

		chk.u_caps = cap_conv("CAP_SYSLOG");
		chk.w_caps = cap_full;

		if (!check_permission(role, def_acl, "", &chk)) {
			fprintf(stderr, "CAP_SYSLOG is not "
				"removed in role %s.  This would allow an "
				"attacker to view OOPs messages in dmesg that contain addresses useful for kernel exploitation.\n\n",
				role->rolename);
			errs_found++;
		}

		chk.u_caps = cap_conv("CAP_SYS_BOOT");
		chk.w_caps = cap_full;

		if (!check_permission(role, def_acl, "", &chk)) {
			fprintf(stderr, "CAP_SYS_BOOT is not "
				"removed in role %s.  This would allow an "
				"attacker to reboot the system or to load a new kernel through the kexec interface .\n\n",
				role->rolename);
			errs_found++;
		}

		chk.u_caps = cap_conv("CAP_NET_ADMIN");
		chk.w_caps = cap_full;

		if (!check_permission(role, def_acl, "", &chk)) {
			fprintf(stderr, "CAP_NET_ADMIN is not "
				"removed for role %s.  This would allow an "
				"attacker to modify your firewall configuration or redirect private information\n\n",
				role->rolename);
			errs_found++;
		}

		chk.u_caps = cap_conv("CAP_NET_BIND_SERVICE");
		chk.w_caps = cap_full;

		if (!check_permission(role, def_acl, "", &chk)) {
			fprintf(stderr, "CAP_NET_BIND_SERVICE is not "
			        "removed for role %s.  This would allow an "
			        "attacker (if he can kill a network daemon) to "
			        "launch a trojaned daemon that could steal privileged information\n\n",
				role->rolename);
			errs_found++;
		}

		chk.u_caps = cap_conv("CAP_SYS_TTY_CONFIG");
		chk.w_caps = cap_full;

		if (!check_permission(role, def_acl, "", &chk)) {
			fprintf(stderr, "CAP_SYS_TTY_CONFIG is not "
				"removed for role %s.  This would allow an "
				"attacker to hijack terminals of "
				"privileged processes\n\n",
				role->rolename);
			errs_found++;
		}


		chk.u_caps = cap_conv("CAP_SETFCAP");
		chk.w_caps = cap_full;

		if (!check_permission(role, def_acl, "", &chk)) {
			fprintf(stderr, "CAP_SETFCAP is not "
				"removed for role %s.  This would allow an "
				"attacker to set and modify file "
				"capabilities.\n\n", role->rolename);
			errs_found++;
		}


		errs_found += check_path_env(role, def_acl);
		errs_found += check_lib_paths(role, def_acl);
		errs_found += check_lilo_conf(role, def_acl);
	}
	/* end of per-role checks */

	errs_found += handle_notrojan_mode();

	check_symlinks();

	if (errs_found) {
		printf("There were %d holes found in your RBAC "
		       "configuration.  These must be fixed before the "
		       "RBAC system will be allowed to be enabled.\n",
		       errs_found);
		exit(EXIT_FAILURE);
	}

	return;
}
