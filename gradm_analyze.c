#include "gradm.h"

static int check_permission(struct role_acl * role, struct proc_acl * def_acl, const char * filename, struct chk_perm * chk)
{
	struct file_acl *tmpf = NULL;
	char * tmpname;

	if(chk->type == CHK_FILE) {
		if((tmpname = calloc(strlen(filename) + 1, sizeof(char))) == NULL)
			failure("calloc");

		strncpy(tmpname, filename, strlen(filename));
	
		  do {
		   for_each_object(tmpf, def_acl->proc_object)
		    if(!strcmp(tmpf->filename, tmpname)) {
		     if(((chk->w_modes == 0xffff) || (tmpf->mode & chk->w_modes)) 
			&& ((chk->u_modes == 0xffff) || !(tmpf->mode & chk->u_modes))) {
		      free(tmpname);
		      return 1;
		     } else {
		      free(tmpname);
		      return 0;
		     }
		    }
		  } while(parent_dir(filename, &tmpname));

		free(tmpname);
	} else if(chk->type == CHK_CAP) {
		if(((chk->w_caps == 0xffffffff) || !(def_acl->cap_drop & chk->w_caps)) 
			&& ((chk->u_caps == 0xffffffff) || (def_acl->cap_drop & chk->u_caps)))
			return 1;
	}		
	
	return 0;
}

static int check_subjects(struct role_acl *role)
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
		if((tmp->filename[0] == '/') && (tmp->filename[1] != '\0'))
		if(!check_permission(role, def_acl, tmp->filename, &chk))
			fprintf(stderr, "Warning: write access is allowed to your " 
				"subject ACL for %s in role %s.  Please ensure that the subject is running with less privilege than the default ACL.\n", tmp->filename, role->rolename);

	return errs_found;
}

static void check_default_objects(struct role_acl *role)
{
	int def_notfound=1;
	struct proc_acl *tmp;
	struct file_acl *tmpf;	

	for_each_subject(tmp, role) {
		for_each_object(tmpf, tmp->proc_object)
			if(!strcmp(tmpf->filename, "/"))
				def_notfound = 0;
		if(def_notfound) {
			fprintf(stderr, "Default ACL object not found for "
					"role %s subject %s\nThe ACL system will "
					"not load until you correct this "
					"error.\n", role->rolename, tmp->filename);
			exit(EXIT_FAILURE);
		}
		def_notfound = 1;
	}

	return;
}

static int check_lilo_conf(struct role_acl *role, struct proc_acl * def_acl)
{
	FILE * liloconf;
	char buf[PATH_MAX];
	struct stat fstat;
	struct chk_perm chk;
	unsigned int errs_found = 0;
	char *p;

	if((liloconf = fopen("/etc/lilo.conf", "r")) == NULL)
		return 0;

	chk.type = CHK_FILE;
	chk.u_modes = GR_WRITE;
	chk.w_modes = 0xffff;

	while(fgets(buf, PATH_MAX - 1, liloconf)) {
		if(buf[strlen(buf) - 1] == '\n')
			buf[strlen(buf) - 1] = '\0';
		if((p = strstr(buf, "image="))) {
			p += 6;	
			if(!stat(p, &fstat) && !check_permission(role, def_acl, p, &chk)) {
				fprintf(stderr, "Write access is allowed by role %s to %s, a kernel "
				       "for your system specified in "
				       "/etc/lilo.conf.\n\n", role->rolename, p);
				errs_found++;
			}
		}
	}	

	fclose(liloconf);

	return errs_found;
}

static int check_lib_paths(struct role_acl *role, struct proc_acl * def_acl)
{
	FILE * ldconf;
	char buf[PATH_MAX];
	struct stat fstat;
	struct chk_perm chk;
	unsigned int errs_found = 0;

	if((ldconf = fopen("/etc/ld.so.conf", "r")) == NULL)
		return 0;

	chk.type = CHK_FILE;
	chk.u_modes = GR_WRITE;
	chk.w_modes = 0xffff;

	while(fgets(buf, PATH_MAX - 1, ldconf)) {
		if(buf[strlen(buf) - 1] == '\n')
			buf[strlen(buf) - 1] = '\0';

		if(!stat(buf, &fstat) && !check_permission(role, def_acl, buf, &chk)) {
			fprintf(stderr, "Write access is allowed by role %s to %s, a directory which "
			       "holds libraries for your system and is included "
			       "in /etc/ld.so.conf.\n\n", role->rolename, buf);
			errs_found++;
		}
	}

	fclose(ldconf);
		
	return errs_found;
}

static int check_path_env(struct role_acl *role, struct proc_acl * def_acl)
{
	char *pathstr, *p, *p2;
	struct stat fstat;
	struct chk_perm chk;
	unsigned int errs_found = 0;

	if((pathstr = getenv("PATH")) == NULL) return 0;

	p = pathstr;

	chk.type = CHK_FILE;
	chk.u_modes = GR_WRITE;
	chk.w_modes = 0xffff;
	
	while((p2 = strchr(p, ':'))) {
		*p2++ = '\0';
		if(!stat(p, &fstat) && !check_permission(role, def_acl, p, &chk)) {
			fprintf(stderr, "Write access is allowed by role %s to %s, a directory which "
			       "holds binaries for your system and is included "
			       "in the PATH environment variable.\n\n", role->rolename, p);
			errs_found++;
		}
		p = p2;
	}

	if(!stat(p, &fstat) && !check_permission(role, def_acl, p, &chk)) {
		fprintf(stderr, "Write access is allowed by role %s to %s, a directory which "
		       "holds binaries for your system and is included "
		       "in the PATH environment variable.\n\n", role->rolename, p);
		errs_found++;
	}

	return errs_found;
}

static int handle_notrojan_mode(void)
{
	struct proc_acl *subj, *subj2;
	struct file_acl *obj, *obj2;
	struct role_acl *role, *role2;
	char *objname;
	int ret = 0;

	for_each_role(role, current_role) {
	for_each_subject(subj, role) {
	    if (!(subj->mode & GR_NOTROJAN)) continue;
	    for_each_object(obj, subj->proc_object) {
		if (!(obj->mode & GR_EXEC)) continue;
		if ((objname = malloc(strlen(obj->filename) + 1)) == NULL)
		    failure("malloc");
		strncpy(objname, obj->filename, strlen(obj->filename));
		do {
		    for_each_role(role2, current_role) {
		    for_each_subject(subj2, role2) {
			if (subj2 == subj || (subj2->filename[0] != '/')) continue;
			for_each_object(obj2, subj2->proc_object) {
			    if (!strcmp(obj2->filename, objname)) {
				if (obj2->mode & GR_WRITE) {
				    ret++;
				    fprintf(stderr, "\'T\' specified in mode for %s."
						    "  %s's executable object %s is "
						    "writable by %s, due to its "
						    "writable object %s.\nThis would "
						    "allow %s to execute trojaned code.\n\n",
						    subj->filename,
						    subj->filename,
						    obj->filename,
						    subj2->filename,
						    obj2->filename,
						    subj->filename);
				}
				break;
			    }
			}
		    }
		    }
		} while(parent_dir(obj->filename, &objname));
		free(objname);
	    }
	}
	}

	return ret;
}					

void analyze_acls(void)
{
	struct proc_acl *def_acl;
	struct chk_perm chk;
	unsigned int errs_found = 0;
	struct role_acl *role;

	for_each_role(role, current_role) {
	if (!strcmp(role->rolename, ":::kernel:::") ||
	    !strcmp(role->rolename, ":::admin:::"))
		continue;

	def_acl = role->root_label;
	if (!def_acl) {
		fprintf(stderr, "There is no default subject for "
			"the role for %s present in your "
			"configuration.\nPlease read the ACL "
			"documentation and create a default ACL "
			"before attempting to enable the ACL "
			"system.\n", role->rolename);
		exit(EXIT_FAILURE);
	}

	check_default_objects(role);
	errs_found += check_subjects(role);

	chk.type = CHK_FILE;
	chk.u_modes = GR_FIND;
	chk.w_modes = 0xffff;
	
	if(!check_permission(role, def_acl, GRSEC_DIR, &chk)) {
		fprintf(stderr, "Viewing access is allowed by role %s to %s, the directory which "
		       "holds ACL and ACL password information.\n\n", role->rolename, GRSEC_DIR);
		errs_found++;
	}

	if(!check_permission(role, def_acl, "/dev/kmem", &chk)) {
		fprintf(stderr, "Viewing access is allowed by role %s to /dev/kmem.  This could "
		       "allow an attacker to modify the code of your "
		       "running kernel.\n\n", role->rolename);
		errs_found++;
	}

	if(!check_permission(role, def_acl, "/dev/mem", &chk)) {
		fprintf(stderr, "Viewing access is allowed by role %s to /dev/mem.  This would "
		       "allow an attacker to modify the code of programs "
		       "running on your system.\n\n", role->rolename);
		errs_found++;
	}

	if(!check_permission(role, def_acl, "/dev/port", &chk)) {
		fprintf(stderr, "Viewing access is allowed by role %s to /dev/port.  This would "
		       "allow an attacker to modify the code of programs "
		       "running on your system.\n\n", role->rolename);
		errs_found++;
	}

	if(!check_permission(role, def_acl, "/proc/kcore", &chk)) {
		fprintf(stderr, "Viewing access is allowed by role %s to /proc/kcore.  This would "
		       "allow an attacker to view the raw memory of processes "
		       "running on your system.\n\n", role->rolename);
		errs_found++;
	}

	chk.u_modes = GR_WRITE;

	if(!check_permission(role, def_acl, "/boot", &chk)) {
		fprintf(stderr, "Writing access is allowed by role %s to /boot, the directory which "
		       "holds boot and kernel information.\n\n", role->rolename);
		errs_found++;
	}


	if(!check_permission(role, def_acl, "/dev", &chk)) {
		fprintf(stderr, "Writing access is allowed by role %s to /dev, the directory which "
		       "holds system devices.\n\n", role->rolename);
		errs_found++;
	}

	if(!check_permission(role, def_acl, "/dev/log", &chk)) {
		fprintf(stderr, "Writing access is allowed by role %s to /dev/log.  This could in some cases allow an attacker"
				" to spoof learning logs on your system.\n\n", role->rolename);
		errs_found++;
	}

	if(!check_permission(role, def_acl, "/root", &chk)) {
		fprintf(stderr, "Writing access is allowed by role %s to /root, the directory which "
		       "holds shell configurations for the root user.  "
			"If writing is allowed to this directory, an attacker "
			"could modify your $PATH environment to fool you "
			"into executing a trojaned gradm.\n\n", role->rolename);
		errs_found++;
	}

	if(!check_permission(role, def_acl, "/proc/sys", &chk)) {
		fprintf(stderr, "Write access is allowed by role %s to /proc/sys, the directory which "
		       "holds entries that allow modifying kernel variables.\n\n", role->rolename);
		errs_found++;
	}

	if(!check_permission(role, def_acl, "/etc", &chk)) {
		fprintf(stderr, "Write access is allowed by role %s to /etc, the directory which "
		       "holds initialization scripts and configuration files.\n\n", role->rolename);
		errs_found++;
	}

	if(!check_permission(role, def_acl, "/lib", &chk)) {
		fprintf(stderr, "Write access is allowed by role %s to /lib, a directory which "
		       "holds system libraries and loadable modules.\n\n", role->rolename);
		errs_found++;
	}

	if(!check_permission(role, def_acl, "/usr/lib", &chk)) {
		fprintf(stderr, "Write access is allowed by role %s to /usr/lib, a directory which "
		       "holds system libraries.\n\n", role->rolename);
		errs_found++;
	}

	chk.u_modes = GR_READ;

	if(!check_permission(role, def_acl, "/dev", &chk)) {
		fprintf(stderr, "Reading access is allowed by role %s to /dev, the directory which "
		       "holds system devices.\n\n", role->rolename);
		errs_found++;
	}

	chk.type = CHK_CAP;
	chk.u_caps = (1 << CAP_SYS_MODULE) | (1 << CAP_SYS_RAWIO) | (1 << CAP_MKNOD);;
	chk.w_caps = 0xffffffff;

	if(!check_permission(role, def_acl, "", &chk)) {
		fprintf(stderr, "CAP_SYS_MODULE, CAP_SYS_RAWIO, and CAP_MKNOD are both not "
		       "removed in role %s.  This would allow an "
		       "attacker to modify the kernel by means of a "
		       "module or corrupt devices on your system.\n\n", role->rolename);
		errs_found++;
	}

	errs_found += check_path_env(role, def_acl);
	errs_found += check_lib_paths(role, def_acl);
	errs_found += check_lilo_conf(role, def_acl);
	
	errs_found += handle_notrojan_mode();

	if(errs_found) {
		printf("There were %d holes found in your ACL "
			"configuration.  These must be fixed before the "
			"ACL system will be allowed to be enabled.\n",errs_found);
		exit(EXIT_FAILURE);
	}

	}

	return;
}	
