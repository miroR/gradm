#include "gradm.h"

static void
show_version(void)
{
	printf("gradm v%s\n"
	       "Licensed under the GNU General Public License (GPL) version 2 or higher\n"
	       "Copyright 2002,2003,2004  Brad Spengler\n", GR_VERSION);
	exit(EXIT_SUCCESS);
}

static void
show_help(void)
{
	printf("gradm %s\n"
	       "grsecurity administration program\n\n"
	       "Usage: gradm [option] ... \n\n"
	       "Examples:\n"
	       "	gradm -P\n"
	       "	gradm -F -L /etc/grsec/learning.logs -O /etc/grsec/policy\n"
	       "Options:\n"
	       "	-E, --enable	Enable the grsecurity RBAC system\n"
	       "	-D, --disable	Disable the grsecurity RBAC system\n"
	       "	-S, --status	Check status of RBAC system\n"
	       "	-F, --fulllearn Enable full system learning\n"
	       "	-P [rolename], --passwd\n"
	       "			Create password for RBAC administration\n"
	       "			or a special role\n"
	       "	-R, --reload	Reload the RBAC system while in admin mode\n"
	       "	-L <filename>, --learn\n"
	       "			Specify the pathname for learning logs\n"
	       "	-O <filename>, --output\n"
	       "			Specify where to place policies generated from learning mode\n"
	       "	-M <filename|uid>, --modsegv\n"
	       "			Remove a ban on a specific file or UID\n"
	       "	-a <rolename> , --auth\n"
	       "			Authenticates to a special role that requires auth\n"
	       "	-u, --unauth    Remove yourself from your current special role\n"
	       "	-n <rolename> , --noauth\n"
	       "			Authenticates to a special role that doesn't require auth\n"
	       "	-V, --verbose   Display verbose policy statistics when enabling system\n"
	       "	-h, --help	Display this help\n"
	       "	-v, --version	Display version information\n",
	       GR_VERSION);

	exit(EXIT_SUCCESS);
	return;
}

static void
conv_name_to_num(const char *filename, gr_dev_t *dev, ino_t * inode)
{
	struct stat fstat;

	if (stat(filename, &fstat)) {
		fprintf(stderr, "Unable to stat %s: %s\n", filename,
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	*dev = MKDEV(MAJOR(fstat.st_dev), MINOR(fstat.st_dev));
	*inode = fstat.st_ino;

	return;
}

void verbose_stats(void)
{
	struct role_acl *rtmp;
	struct proc_acl *stmp;
	struct file_acl *otmp;
	unsigned int uroles=0, groles=0, saroles=0, snroles=0, troles=0;
	unsigned int usubjs=0, gsubjs=0, sasubjs=0, snsubjs=0, ksubjs=0, smsubjs=0, tsubjs=0, nsubjs=0;
	unsigned int chsobjs=0, tobjs=0;

	for_each_role(rtmp, current_role) {
		troles++;
		if (rtmp->roletype & GR_ROLE_SPECIAL) {
			if (rtmp->roletype & GR_ROLE_NOPW)
				snroles++;
			else
				saroles++;
		} else if (rtmp->roletype & GR_ROLE_USER)
			uroles++;
		else if (rtmp->roletype & GR_ROLE_GROUP)
			groles++;
		
		for_each_subject(stmp, rtmp) {
			tsubjs++;
			if (rtmp->roletype & GR_ROLE_SPECIAL) {
				if (rtmp->roletype & GR_ROLE_NOPW)
					snsubjs++;
				else
					sasubjs++;
			} else if (rtmp->roletype & GR_ROLE_USER)
				usubjs++;
			else if (rtmp->roletype & GR_ROLE_GROUP)
				gsubjs++;

			if (!(stmp->mode & GR_PROTECTED))
				ksubjs++;
			if (!(stmp->mode & GR_PROTSHM))
				shmsubjs++;

			for_each_object(otmp, stmp) {
				tobjs++;
				if (otmp->mode & GR_SETID)
					chsobjs++;
			}
		}
	}				

	printf("Policy statistics:\n");
	printf("-----------------------------------------------\n");
	printf("\tRole summary:\n");
	printf("\t%d user roles\n", uroles);
	printf("\t%d group roles\n", groles);
	printf("\t%d special roles with authentication\n", saroles);
	printf("\t%d special roles without authentication\n", snroles);
	printf("\t%d total roles\n\n", troles);
	printf("\tSubject summary:\n");
	printf("\t%d subjects in user roles\n", usubjs);
	printf("\t%d subjects in group roles\n", gsubjs);
	printf("\t%d subjects in special roles with authentication\n", sasubjs);
	printf("\t%d subjects in special roles without authentication\n", snsubjs);
	printf("\t%d nested subjects\n", nsubjs);
	printf("\t%d subjects can be killed by outside processes\n", ksubjs);
	printf("\t%d subjects have unprotected shared memory\n", smsubjs);
	printf("\t%d total subjects\n\n", tsubjs);
	printf("\tObject summary:\n");
	printf("\t%d objects in non-admin roles allow chmod +s\n", chsobjs);
	printf("\t%d total objects\n\n", tobjs);

	return;
}

void
parse_args(int argc, char *argv[])
{
	int next_option = 0;
	int err;
	int verbose = 0;
	char *output_log = NULL;
	char *learn_log = NULL;
	int gr_learn = 0;
	int gr_output = 0;
	int gr_enable = 0;
	int gr_fulllearn = 0;
	struct gr_pw_entry entry;
	struct gr_arg_wrapper *grarg;
	char cwd[PATH_MAX];
	const char *const short_opts = "SVEFuDP::RL:O:M:a:n:hv";
	const struct option long_opts[] = {
		{"help", 0, NULL, 'h'},
		{"version", 0, NULL, 'v'},
		{"status", 0, NULL, 'S'},
		{"enable", 0, NULL, 'E'},
		{"disable", 0, NULL, 'D'},
		{"passwd", 2, NULL, 'P'},
		{"auth", 1, NULL, 'a'},
		{"noauth", 1, NULL, 'n'},
		{"reload", 0, NULL, 'R'},
		{"modsegv", 1, NULL, 'M'},
		{"verbose", 0, NULL, 'V'},
		{"learn", 1, NULL, 'L'},
		{"fulllearn", 0, NULL, 'F'},
		{"output", 1, NULL, 'O'},
		{"unauth", 0, NULL, 'u'},
		{NULL, 0, NULL, 0}
	};

	getcwd(cwd, PATH_MAX - 1);

	err = mlock(&entry, sizeof (entry));
	if (err && !getuid())
		fprintf(stderr, "Warning: Unable to lock password "
			"into physical memory.\n");

	memset(&entry, 0, sizeof (struct gr_pw_entry));

	if (argc < 2)
		show_help();

	while ((next_option =
		getopt_long(argc, argv, short_opts, long_opts, NULL)) != -1) {

		switch (next_option) {
		case 'V':
			verbose = 1;
			break;
		case 'S':
			if (argc > 2)
				show_help();
			check_acl_status(GRADM_STATUS);
			break;
		case 'E':
			if (argc > 5)
				show_help();
			entry.mode = GRADM_ENABLE;
			check_acl_status(entry.mode);
			parse_acls();
			expand_acls();
			analyze_acls();
			gr_enable = 1;
			break;
		case 'F':
			if (argc > 7)
				show_help();
			entry.mode = GRADM_ENABLE;
			gr_fulllearn = 1;
			gr_enable = 1;
			break;
		case 'u':
			if (argc > 2)
				show_help();
			entry.mode = GRADM_UNSPROLE;
			check_acl_status(entry.mode);
			grarg = conv_user_to_kernel(&entry);
			transmit_to_kernel(grarg);
			break;
		case 'R':
			if (argc > 3)
				show_help();
			entry.mode = GRADM_RELOAD;
			check_acl_status(entry.mode);
			get_user_passwd(&entry, GR_PWONLY);
			parse_acls();
			expand_acls();
			analyze_acls();
			grarg = conv_user_to_kernel(&entry);
			read_saltandpass(entry.rolename, grarg->arg->salt,
					 grarg->arg->sum);
			transmit_to_kernel(grarg);
			break;
		case 'M':
			if ((argc != 3) || (optind > argc)
			    || (strlen(optarg) < 1))
				show_help();
			entry.mode = GRADM_MODSEGV;
			check_acl_status(entry.mode);
			get_user_passwd(&entry, GR_PWONLY);

			if (isdigit(optarg[0]))
				entry.segv_uid = atoi(optarg);
			else
				conv_name_to_num(optarg, &entry.segv_dev,
						 &entry.segv_inode);
			grarg = conv_user_to_kernel(&entry);
			transmit_to_kernel(grarg);
			exit(EXIT_SUCCESS);
			break;
		case 'D':
			if (argc > 2)
				show_help();
			entry.mode = GRADM_DISABLE;
			check_acl_status(entry.mode);
			get_user_passwd(&entry, GR_PWONLY);
			grarg = conv_user_to_kernel(&entry);
			transmit_to_kernel(grarg);
			exit(EXIT_SUCCESS);
			break;
		case 'L':
			if (argc > 7 || argc < 3)
				show_help();
			gr_learn = 1;
			if (optarg) {
				char pathbuf[PATH_MAX];
				if (*optarg == '/')
					learn_log = strdup(optarg);
				else {
					strcpy(pathbuf, cwd);
					if (strlen(optarg) + strlen(pathbuf) + 2 > PATH_MAX) {
						fprintf(stderr, "Unable to open %s for learning logs.\n", optarg);
						exit(EXIT_FAILURE);
					}
					strcat(pathbuf, "/");
					strcat(pathbuf, optarg);
					learn_log = strdup(pathbuf);
				}
			}
			break;
		case 'O':
			if (argc > 6 || argc < 3)
				show_help();
			gr_output = 1;
			if (optarg)
				output_log = strdup(optarg);
			break;
		case 'P':
			if (argc > 3)
				show_help();
			if (argc == 3) {
				strncpy(entry.rolename, argv[2], GR_SPROLE_LEN);
				entry.rolename[GR_SPROLE_LEN - 1] = '\0';
				printf("Setting up password for role %s\n",
				       entry.rolename);
			} else
				printf("Setting up grsecurity RBAC password\n");
			get_user_passwd(&entry, GR_PWANDSUM);
			generate_salt(&entry);
			generate_hash(&entry);
			write_user_passwd(&entry);
			memset(&entry, 0, sizeof (struct gr_pw_entry));
			exit(EXIT_SUCCESS);
			break;
		case 'a':
			if (argc != 3)
				show_help();
			strncpy(entry.rolename, argv[2], GR_SPROLE_LEN);
			entry.rolename[GR_SPROLE_LEN - 1] = '\0';
			entry.mode = GRADM_SPROLE;
			check_acl_status(entry.mode);
			get_user_passwd(&entry, GR_PWONLY);
			grarg = conv_user_to_kernel(&entry);
			transmit_to_kernel(grarg);
			exit(EXIT_SUCCESS);
			break;
		case 'n':
			if (argc != 3)
				show_help();
			strncpy(entry.rolename, argv[2], GR_SPROLE_LEN);
			entry.rolename[GR_SPROLE_LEN - 1] = '\0';
			entry.mode = GRADM_SPROLE;
			check_acl_status(entry.mode);
			grarg = conv_user_to_kernel(&entry);
			transmit_to_kernel(grarg);
			exit(EXIT_SUCCESS);
			break;
		case 'v':
			if (argc > 2)
				show_help();
			show_version();
			break;
		case 'h':
			show_help();
			break;
		default:
			show_help();
			break;
		}
	}

	if ((gr_output && !gr_learn)) {
		fprintf(stderr, "-L and -O must be used together.\n");
		exit(EXIT_FAILURE);
	}

	if ((gr_fulllearn && !gr_learn)) {
		fprintf(stderr, "-L and -F must be used together.\n");
		exit(EXIT_FAILURE);
	}

	if (gr_fulllearn && gr_learn && gr_output)
		gr_enable = 0;

	if (gr_enable) {
		check_acl_status(entry.mode);
		if (verbose)
			verbose_stats();
		if (gr_fulllearn)
			add_fulllearn_acl();
		if (gr_learn) {
			start_grlearn(learn_log);
			free(learn_log);
		}
		grarg = conv_user_to_kernel(&entry);
		read_saltandpass(entry.rolename, grarg->arg->salt,
				 grarg->arg->sum);
		transmit_to_kernel(grarg);
	} else if (gr_learn && gr_output) {
		FILE *stream;

		if (!strcmp(output_log, "stdout"))
			stream = stdout;
		else if (!strcmp(output_log, "stderr"))
			stream = stderr;
		else {
			stream = fopen(output_log, "a");
			if (!stream) {
				fprintf(stderr,
					"Unable to open %s for writing.\n"
					"Error: %s\n", output_log,
					strerror(errno));
				exit(EXIT_FAILURE);
			}
		}

		if (gr_fulllearn)
			generate_full_learned_acls(learn_log, stream);
		else
			handle_learn_logs(learn_log, stream);

		free(learn_log);
		free(output_log);
	}
	return;
}
