#include "gradm.h"

extern FILE *gradmin;
extern int gradmparse(void);

void
add_role_transition(struct role_acl *role, char *rolename)
{
	struct role_transition **roletpp;
	struct role_transition *roletp;

	roletp =
	    (struct role_transition *) calloc(1,
					      sizeof (struct role_transition));
	if (!roletp)
		failure("calloc");

	roletpp = &(role->transitions);

	if (*roletpp)
		(*roletpp)->next = roletp;

	roletp->prev = *roletpp;

	roletp->rolename = rolename;

	*roletpp = roletp;

	return;
}

static struct deleted_file *
is_deleted_file_dupe(const char *filename)
{
	struct deleted_file *tmp;

	tmp = deleted_files;

	do {
		if (!strcmp(filename, tmp->filename))
			return tmp;
	} while ((tmp = tmp->next));

	return NULL;
}

static struct deleted_file *
add_deleted_file(char *filename)
{
	struct deleted_file *dfile;
	struct deleted_file *retfile;
	static ino_t ino = 0;

	ino++;

	if (!deleted_files) {
		deleted_files = malloc(sizeof (struct deleted_file));
		if (!deleted_files)
			failure("malloc");
		deleted_files->filename = filename;
		deleted_files->ino = ino;
		deleted_files->next = NULL;
	} else {
		retfile = is_deleted_file_dupe(filename);
		if (retfile)
			return retfile;
		dfile = malloc(sizeof (struct deleted_file));
		if (!dfile)
			failure("malloc");
		dfile->filename = filename;
		dfile->ino = ino;
		dfile->next = deleted_files;
		deleted_files = dfile;
	}

	return deleted_files;
}

static int
is_role_dupe(struct role_acl *role, const char *rolename, const __u16 type)
{
	struct role_acl *tmp;

	for_each_role(tmp, role)
	    if ((tmp->roletype & type) && !strcmp(tmp->rolename, rolename))
		return 1;

	return 0;
}

static struct file_acl *
is_proc_object_dupe(struct file_acl *filp, struct file_acl *filp2)
{
	struct file_acl *tmp;

	for_each_object(tmp, filp)
	    if (((tmp->inode == filp2->inode) && (tmp->dev == filp2->dev)) ||
		!strcmp(tmp->filename, filp2->filename))
		return tmp;

	return NULL;
}

static struct proc_acl *
is_proc_subject_dupe(struct role_acl *role, struct proc_acl *proc)
{
	struct proc_acl *tmp;

	for_each_subject(tmp, role)
	    if (((tmp->inode == proc->inode) && (tmp->dev == proc->dev)) ||
		!strcmp(tmp->filename, proc->filename))
		return tmp;

	return NULL;
}

int
add_role_acl(struct role_acl **role, char *rolename, __u16 type, int ignore)
{
	struct role_acl *rtmp;
	struct passwd *pwd;
	struct group *grp;

	if (!rolename) {
		fprintf(stderr, "Out of memory.\n");
		exit(EXIT_FAILURE);
	}

	if ((rtmp =
	     (struct role_acl *) calloc(1, sizeof (struct role_acl))) == NULL)
		failure("calloc");

	rtmp->roletype = type;
	rtmp->rolename = rolename;

	if (strcmp(rolename, "default") && (type & GR_ROLE_DEFAULT)) {
		fprintf(stderr, "No role type specified for %s on line %lu "
			"of %s.\nThe ACL system will not be allowed to be "
			"enabled until this error is fixed.\n", rolename,
			lineno, current_acl_file);
		return 0;
	}

	if (is_role_dupe(*role, rtmp->rolename, rtmp->roletype)) {
		fprintf(stderr, "Duplicate role on line %lu of %s.\n"
			"The ACL system will not be allowed to be "
			"enabled until this error is fixed.\n",
			lineno, current_acl_file);
		return 0;
	}

	if (ignore)
		rtmp->uidgid = special_role_uid++;
	else if (strcmp(rolename, "default") || !(type & GR_ROLE_DEFAULT)) {
		if (type & GR_ROLE_USER) {
			pwd = getpwnam(rolename);

			if (!pwd) {
				fprintf(stderr, "User %s on line %lu of %s "
					"does not exist.\nThe ACL system will "
					"not be allowed to be enabled until "
					"this error is fixed.\n", rolename,
					lineno, current_acl_file);
				return 0;
			}

			rtmp->uidgid = pwd->pw_uid;
		} else if (type & GR_ROLE_GROUP) {
			grp = getgrnam(rolename);

			if (!grp) {
				fprintf(stderr, "Group %s on line %lu of %s "
					"does not exist.\nThe ACL system will "
					"not be allowed to be enabled until "
					"this error is fixed.\n", rolename,
					lineno, current_acl_file);
				return 0;
			}

			rtmp->uidgid = grp->gr_gid;
		} else if (type & GR_ROLE_SPECIAL) {
			rtmp->uidgid = special_role_uid++;
		}
	}

	if (*role)
		(*role)->next = rtmp;

	rtmp->prev = *role;

	*role = rtmp;

	if (type & GR_ROLE_AUTH)
		add_gradm_acl(*role);
	if (!(type & GR_ROLE_SPECIAL))
		add_grlearn_acl(*role);

	return 1;
}

static int
add_globbing_file(struct proc_acl *subject, char *filename,
		  __u32 mode, int type)
{
	char tmp[PATH_MAX] = { 0 };
	unsigned int len = strlen(filename);
	unsigned long i;
	char *last;
	glob_t pglob;
	int err;
	struct file_acl ftmp, ftmp2;
	struct stat fstat;

	while (len--) {
		switch (*(filename + len)) {
		case '*':
		case '?':
		case '/':
			goto out;
		}
	}
      out:
	/* this means the globbing was done before the last path component
	   therefore we want to add objects even if they don't exist
	   eg: /home/ * /test would match /home/user1/test, /home/user2/test,
	   /home/user3/test....etc even if the "test" file did not exist
	   in their homedirs
	 */
	if (*(filename + len) == '/') {
		len = strlen(filename);
		while (len--) {
			switch (*(filename + len)) {
			case '*':
			case '?':
				goto out2;
			}
		}
	      out2:
		last = strchr(filename + len, '/');
		*last = '\0';
		last++;

		err = glob(filename, GLOB_PERIOD | GLOB_ONLYDIR, NULL, &pglob);

		if (err) {
			fprintf(stderr, "glob() error \"%s\" encountered"
				" on line %lu of %s.\n"
				"The ACL system will not load until this"
				" error is fixed.\n", strerror(errno), lineno,
				current_acl_file);
			exit(EXIT_FAILURE);
		}

		for (i = 0; i < pglob.gl_pathc; i++) {
			len = strlen(*(pglob.gl_pathv + i));

			if (len > 3) {
				char *p;
				p = (*(pglob.gl_pathv + i) + len - 3);
				if (!strcmp(p, "/.."))
					continue;
				p++;
				if (!strcmp(p, "/."))
					continue;
			}

			snprintf(tmp, sizeof (tmp), "%s/%s",
				 *(pglob.gl_pathv + i), last);

			ftmp.filename = tmp;

			if (!lstat(ftmp.filename, &fstat)) {
				ftmp.inode = fstat.st_ino;
				ftmp.dev =
				    MKDEV(MAJOR(fstat.st_dev),
					  MINOR(fstat.st_dev));

				if (S_ISLNK(fstat.st_mode)) {
					char buf[PATH_MAX];
					memset(&buf, 0, sizeof (buf));
					realpath(ftmp.filename, buf);
					ftmp2.filename = buf;

					if (!lstat(ftmp2.filename, &fstat)) {
						ftmp2.inode = fstat.st_ino;
						ftmp2.dev =
						    MKDEV(MAJOR(fstat.st_dev),
							  MINOR(fstat.st_dev));
						if (is_proc_object_dupe
						    (subject->proc_object,
						     &ftmp2))
							continue;
						if (!add_proc_object_acl
						    (subject, strdup(buf), mode,
						     type | GR_GLOB))
							return 0;
					}
				}
				if (is_proc_object_dupe
				    (subject->proc_object, &ftmp))
					continue;
				if (!add_proc_object_acl
				    (subject, strdup(tmp), mode, type))
					return 0;
			}

		}
		globfree(&pglob);
	} else {
		err = glob(filename, GLOB_PERIOD, NULL, &pglob);

		if (err) {
			fprintf(stderr, "glob() error \"%s\" encountered"
				" on line %lu of %s.\n"
				"The ACL system will not load until this"
				" error is fixed.\n", strerror(errno), lineno,
				current_acl_file);
			exit(EXIT_FAILURE);
		}

		for (i = 0; i < pglob.gl_pathc; i++) {
			len = strlen(*(pglob.gl_pathv + i));

			if (len > 3) {
				char *p;
				p = (*(pglob.gl_pathv + i) + len - 3);
				if (!strcmp(p, "/.."))
					continue;
				p++;
				if (!strcmp(p, "/."))
					continue;
			}

			ftmp.filename = *(pglob.gl_pathv + i);

			if (!stat(ftmp.filename, &fstat)) {
				ftmp.inode = fstat.st_ino;
				ftmp.dev =
				    MKDEV(MAJOR(fstat.st_dev),
					  MINOR(fstat.st_dev));

				if (S_ISLNK(fstat.st_mode)) {
					char buf[PATH_MAX];
					memset(&buf, 0, sizeof (buf));
					realpath(ftmp.filename, buf);
					ftmp2.filename = buf;

					if (!lstat(ftmp2.filename, &fstat)) {
						ftmp2.inode = fstat.st_ino;
						ftmp2.dev =
						    MKDEV(MAJOR(fstat.st_dev),
							  MINOR(fstat.st_dev));

						if (is_proc_object_dupe
						    (subject->proc_object,
						     &ftmp2))
							continue;
						if (!add_proc_object_acl
						    (subject, strdup(buf), mode,
						     type | GR_GLOB))
							return 0;
					}
				}
				if (is_proc_object_dupe
				    (subject->proc_object, &ftmp))
					continue;
				if (!add_proc_object_acl
				    (subject, *(pglob.gl_pathv + i), mode,
				     type))
					return 0;
			}
		}
	}

	return 1;
}

static void
display_all_dupes(struct proc_acl *subject, struct file_acl *filp2)
{
	struct file_acl *tmp = subject->proc_object;
	struct stat fstat;
	struct file_acl ftmp;

	for_each_object(tmp, subject->proc_object)
	    if (!stat(tmp->filename, &fstat)) {
		ftmp.inode = fstat.st_ino;
		ftmp.dev = MKDEV(MAJOR(fstat.st_dev), MINOR(fstat.st_dev));
		if (ftmp.inode == filp2->inode && ftmp.dev == filp2->dev)
			fprintf(stderr, "%s\n", tmp->filename);
	}

	return;
}

int
add_proc_object_acl(struct proc_acl *subject, char *filename,
		    __u32 mode, int type)
{
	struct file_acl *p;
	struct file_acl *p2;
	struct file_acl **filp;
	struct stat fstat;
	struct deleted_file *dfile;
	unsigned int file_len = strlen(filename) + 1;

	if (!subject) {
		fprintf(stderr, "Error on line %lu of %s.  Attempt to "
			"add an object without a subject declaration.\n"
			"The ACL system will not load until this "
			"error is fixed.\n", lineno, current_acl_file);
		return 0;
	}

	filp = &(subject->proc_object);

	if (!filename) {
		fprintf(stderr, "Out of memory.\n");
		exit(EXIT_FAILURE);
	}

	if (strchr(filename, '?') || strchr(filename, '*'))
		return add_globbing_file(subject, filename, mode, type);

	if (lstat(filename, &fstat)) {
		dfile = add_deleted_file(filename);
		fstat.st_ino = dfile->ino;
		fstat.st_dev = 0;
		mode |= GR_DELETED;
	} else if (S_ISLNK(fstat.st_mode) && !(type & GR_GLOB)) {
		char buf[PATH_MAX];
		memset(&buf, 0, sizeof (buf));
		realpath(filename, buf);
		if (!add_proc_object_acl(subject, strdup(buf), mode, type | GR_SYMLINK))
			return 0;
	}

	if ((p =
	     (struct file_acl *) calloc(1, sizeof (struct file_acl))) == NULL)
		failure("calloc");

	if (*filp)
		(*filp)->next = p;

	p->prev = *filp;

	if ((filename[file_len - 2] == '/') && file_len != 2)
		filename[file_len - 2] = '\0';

	if (file_len > PATH_MAX) {
		fprintf(stderr, "Filename too long on line %lu of file %s.\n",
			lineno, current_acl_file);
		exit(EXIT_FAILURE);
	}

	p->filename = filename;
	p->mode = mode;
	p->inode = fstat.st_ino;
	p->dev = MKDEV(MAJOR(fstat.st_dev), MINOR(fstat.st_dev));

	if (type & GR_FLEARN) {
		struct file_acl *tmp = *filp;

		for_each_object(tmp, *filp) {
			if (!strcmp(tmp->filename, p->filename) ||
			    ((tmp->inode == p->inode)
			     && (tmp->dev == p->dev))) {
				tmp->mode |= mode;
				return 1;
			}
		}
	} else if ((p2 = is_proc_object_dupe(*filp, p))) {
		if (type & GR_SYMLINK)
			return 0;
		fprintf(stderr, "Duplicate ACL entry found for \"%s\""
			" on line %lu of %s.\n"
			"\"%s\" references the same object as the following object(s):\n",
			p->filename, lineno, current_acl_file, p->filename);
		display_all_dupes(subject, p);
		fprintf(stderr, "specified on an earlier line."
			"The ACL system will not load until this"
			" error is fixed.\n");
		return 0;
	}

	*filp = p;

	return 1;
}

int
add_proc_subject_acl(struct role_acl *role, char *filename, __u32 mode, int flag)
{
	struct proc_acl *p;
	struct proc_acl *p2;
	struct proc_acl *oldp;
	struct deleted_file *dfile;
	struct ip_acl *tmpi;
	struct stat fstat;
	unsigned short i;
	unsigned int file_len;

	if (!role) {
		fprintf(stderr, "Error on line %lu of %s.  Attempt to "
			"add a subject without a role declaration.\n"
			"The ACL system will not load until this "
			"error is fixed.\n", lineno, current_acl_file);
		return 0;
	}

	oldp = role->proc_subject;

	if (!filename) {
		fprintf(stderr, "Out of memory.\n");
		exit(EXIT_FAILURE);
	}

	file_len = strlen(filename) + 1;

	if (stat(filename, &fstat)) {
		dfile = add_deleted_file(filename);
		fstat.st_ino = dfile->ino;
		fstat.st_dev = 0;
		mode |= GR_DELETED;
	}

	if ((p =
	     (struct proc_acl *) calloc(1, sizeof (struct proc_acl))) == NULL)
		failure("calloc");

	if (oldp)
		oldp->next = p;

	p->prev = oldp;

	if (!strcmp(filename, "/") && !(flag & GR_FFAKE))
		role->root_label = p;

	if ((filename[file_len - 2] == '/') && file_len != 2)
		filename[file_len - 2] = '\0';

	if (file_len > PATH_MAX) {
		fprintf(stderr, "Filename too long on line %lu of file %s.\n",
			lineno, current_acl_file);
		exit(EXIT_FAILURE);
	}

	p->filename = filename;
	p->mode = mode;

	p->dev = MKDEV(MAJOR(fstat.st_dev), MINOR(fstat.st_dev));
	p->inode = fstat.st_ino;

	if (!(flag & GR_FFAKE) && (p2 = is_proc_subject_dupe(role, p))) {
		fprintf(stderr, "Duplicate ACL entry found for \"%s\""
			" on line %lu of %s.\n"
			"\"%s\" references the same object as \"%s\""
			" specified on an earlier line.\n"
			"The ACL system will not load until this"
			" error is fixed.\n", p->filename, lineno,
			current_acl_file, p->filename, p2->filename);
		return 0;
	}

	role->proc_subject = p;
	current_subject = p;

	return 1;
}

__u16
role_mode_conv(const char *mode)
{
	int len = strlen(mode) - 1;
	__u16 retmode = GR_ROLE_DEFAULT;

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
		case 'A':
			retmode |= GR_ROLE_GOD;
			break;
		case 'N':
			retmode |= GR_ROLE_NOPW;
			break;
		case 'G':
			retmode |= GR_ROLE_AUTH;
			break;
		}
	}

	return retmode;
}

__u32
proc_subject_mode_conv(const char *mode)
{
	int i;
	__u32 retmode = 0;

	retmode |= GR_FIND;

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
		case 'P':
			retmode |= GR_PAXPAGE;
			break;
		case 'R':
			retmode |= GR_PAXRANDMMAP;
			break;
		case 'M':
			retmode |= GR_PAXMPROTECT;
			break;
		case 'S':
			retmode |= GR_PAXSEGM;
			break;
		case 'G':
			retmode |= GR_PAXGCC;
			break;
		case 'X':
			retmode |= GR_PAXRANDEXEC;
			break;
		case 'O':
			retmode |= GR_IGNORE;
			break;
		case 'o':
			retmode |= GR_OVERRIDE;
			break;
		case 'l':
			retmode |= GR_LEARN;
			break;
		case 'h':
			retmode &= ~GR_FIND;
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
		default:
			fprintf(stderr, "Invalid proc subject mode "
				"\'%c\' found on line %lu "
				"of %s\n", mode[i], lineno, current_acl_file);
		}
	}

	return retmode;
}

__u32
proc_object_mode_conv(const char *mode)
{
	int i;
	__u32 retmode = 0;

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
		case 's':
			retmode |= GR_SUPPRESS;
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

	add_kernel_acl();

	gradmin = open_acl_file(GR_ACL_PATH);
	change_current_acl_file(GR_ACL_PATH);
	gradmparse();
	fclose(gradmin);

	return;
}

static void
setup_special_roles(struct gr_arg *grarg)
{
	struct role_acl *rtmp = NULL;
	struct gr_pw_entry entry;
	int err;
	__u16 i = 0;

	memset(&entry, 0, sizeof (struct gr_pw_entry));

	err = mlock(&entry, sizeof (struct gr_pw_entry));
	if (err && !getuid())
		fprintf(stderr, "Warning, unable to lock authentication "
			"structure in physical memory.\n");

	for_each_role(rtmp, current_role) {
		if (rtmp->roletype & GR_ROLE_SPECIAL
		    && !(rtmp->roletype & GR_ROLE_NOPW)) {
			strncpy(entry.rolename, rtmp->rolename, GR_SPROLE_LEN);
			entry.rolename[GR_SPROLE_LEN - 1] = '\0';
			if (!read_saltandpass
			    (entry.rolename, entry.salt, entry.sum)) {
				fprintf(stderr,
					"No password exists for special "
					"role %s.\n  Run gradm -P %s to set up a password "
					"for the role.\n", rtmp->rolename,
					rtmp->rolename);
				exit(EXIT_FAILURE);
			}
			grarg->sprole_pws[i].rolename =
			    (unsigned char *) rtmp->rolename;
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

struct gr_arg *
conv_user_to_kernel(struct gr_pw_entry *entry)
{
	struct gr_arg *retarg;
	struct user_acl_role_db *role_db;
	struct role_acl *rtmp = NULL;
	struct proc_acl *tmp = NULL;
	struct file_acl *tmpf = NULL;
	struct role_allowed_ip *atmp = NULL;
	struct role_transition *trtmp = NULL;
	struct ip_acl *tmpi = NULL;
	struct ip_acl *i_tmp = NULL;
	struct role_acl **r_tmp = NULL;
	struct ip_acl **i_table = NULL;
	unsigned long facls = 0;
	unsigned long tpacls = 0;
	unsigned long racls = 0;
	unsigned long iacls = 0;
	unsigned long tiacls = 0;
	unsigned long aacls = 0;
	unsigned long tracls = 0;
	unsigned long i = 0;
	__u16 sproles = 0;
	int err;

	for_each_role(rtmp, current_role) {
		racls++;
		if (rtmp->roletype & GR_ROLE_SPECIAL
		    && !(rtmp->roletype & GR_ROLE_NOPW))
			sproles++;

		for_each_allowed_ip(atmp, rtmp->allowed_ips)
		    aacls++;

		for_each_transition(trtmp, rtmp->transitions)
		    tracls++;

		for_each_subject(tmp, rtmp) {
			tpacls++;
			for_each_object(tmpi, tmp->ip_object)
			    tiacls++;
			for_each_object(tmpf, tmp->proc_object)
			    facls++;
		}
	}

	if ((retarg =
	     (struct gr_arg *) calloc(1, sizeof (struct gr_arg))) == NULL)
		failure("calloc");

	err = mlock(retarg, sizeof (struct gr_arg));
	if (err && !getuid())
		fprintf(stderr, "Warning, unable to lock authentication "
			"structure in physical memory.\n");

	if (!racls && !tpacls && !facls)	// we are disabling, don't want to calloc 0
		goto set_pw;

	if ((retarg->sprole_pws =
	     (struct sprole_pw *) calloc(sproles,
					 sizeof (struct sprole_pw))) == NULL)
		failure("calloc");

	err = mlock(retarg->sprole_pws, sproles * sizeof (struct sprole_pw));
	if (err && !getuid())
		fprintf(stderr, "Warning, unable to lock authentication "
			"structure in physical memory.\n");

	setup_special_roles(retarg);

	retarg->num_sprole_pws = sproles;

	if ((role_db =
	     (struct user_acl_role_db *) calloc(1,
						sizeof (struct
							user_acl_role_db))) ==
	    NULL)
		failure("calloc");

	role_db->r_entries = racls;
	role_db->s_entries = tpacls;
	role_db->i_entries = tiacls;
	role_db->o_entries = facls;
	role_db->a_entries = aacls;
	role_db->t_entries = tracls;

	if ((r_tmp = role_db->r_table =
	     (struct role_acl **) calloc(racls,
					 sizeof (struct role_acl *))) == NULL)
		failure("calloc");

	for_each_role(rtmp, current_role) {
		*r_tmp = rtmp;
		for_each_subject(tmp, rtmp) {
			iacls = 0;
			for_each_object(tmpi, tmp->ip_object)
			    iacls++;
			if (iacls) {
				i_table =
				    (struct ip_acl **) calloc(iacls,
							      sizeof (struct
								      ip_acl
								      *));
				if (!i_table)
					failure("calloc");
				i = 0;
				for_each_object(tmpi, tmp->ip_object) {
					i_tmp =
					    (struct ip_acl *) calloc(1,
								     sizeof
								     (struct
								      ip_acl));
					memcpy(i_tmp, tmpi,
					       sizeof (struct ip_acl));
					*(i_table + i) = i_tmp;
					i++;
				}
				tmp->ips = i_table;
				tmp->ip_num = iacls;
			} else {
				tmp->ips = NULL;
				tmp->ip_num = 0;
			}
		}
		r_tmp++;
	}

	memcpy(&retarg->role_db, role_db, sizeof (struct user_acl_role_db));
      set_pw:

	strncpy(retarg->pw, entry->passwd, GR_PW_LEN - 1);
	retarg->pw[GR_PW_LEN - 1] = '\0';
	strncpy(retarg->sp_role, entry->rolename, GR_SPROLE_LEN);
	retarg->sp_role[GR_SPROLE_LEN - 1] = '\0';

	retarg->mode = entry->mode;
	retarg->segv_inode = entry->segv_inode;
	retarg->segv_dev = entry->segv_dev;
	retarg->segv_uid = entry->segv_uid;

	memset(entry, 0, sizeof (struct gr_pw_entry));

	return retarg;
}
