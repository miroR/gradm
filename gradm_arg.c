#include "gradm.h"

static void
show_version(void)
{
	printf("gradm v%s\n"
	       "Licensed under the GNU General Public License (GPL)\n"
	       "Copyright 2002,2003  Brad Spengler\n", GR_VERSION);
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
	       "	gradm -T /bin/su /etc/shadow\n"
	       "Options:\n"
	       "	-E, --enable	Enable the grsecurity ACL system\n"
	       "	-D, --disable	Disable the grsecurity ACL system\n"
	       "	-P [rolename], --passwd\n"
	       "			Create password for ACL administration\n"
	       "			or a special role\n"
	       "	-R, --reload	Reload the ACL system while in admin mode\n"
	       "	-L <filename>, --learn\n"
	       "			Compute new ACLs from learning log\n"
	       "	-O <filename>, --output\n"
	       "			Specify where to place ACLs generated from learning mode\n"
	       "	-M <filename|uid>, --modsegv\n"
	       "			Remove a ban on a specific file or UID\n"
	       "	-a <rolename> , --auth\n"
	       "			Authenticates to a special role that requires auth\n"
	       "	-n <rolename> , --noauth\n"
	       "			Authenticates to a special role that doesn't require auth\n"
	       "	-h, --help	Display this help\n"
	       "	-v, --version	Display version information\n",
	       GR_VERSION);

	exit(EXIT_SUCCESS);
	return;
}

static void
conv_name_to_num(const char *filename, unsigned short *dev, ino_t * inode)
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

void
parse_args(int argc, char *argv[])
{
	int next_option = 0;
	int err;
	char *output_log = NULL;
	char *learn_log = NULL;
	int gr_learn = 0;
	int gr_output = 0;
	struct gr_pw_entry entry;
	struct gr_arg *grarg;
	const char *const short_opts = "EDP::RL:O:M:a:n:hv";
	const struct option long_opts[] = {
		{"help", 0, NULL, 'h'},
		{"version", 0, NULL, 'v'},
		{"enable", 0, NULL, 'E'},
		{"disable", 0, NULL, 'D'},
		{"passwd", 2, NULL, 'P'},
		{"auth", 1, NULL, 'a'},
		{"noauth", 1, NULL, 'n'},
		{"reload", 0, NULL, 'R'},
		{"modsegv", 1, NULL, 'M'},
		{"learn", 1, NULL, 'L'},
		{"output", 1, NULL, 'O'},
		{NULL, 0, NULL, 0}
	};

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
		case 'E':
			if (argc > 2)
				show_help();
			entry.mode = GRADM_ENABLE;
			parse_acls();
			expand_acls();
			analyze_acls();
			start_grlearn(learn_log);
			grarg = conv_user_to_kernel(&entry);
			read_saltandpass(entry.rolename, grarg->salt,
					 grarg->sum);
			transmit_to_kernel(grarg, sizeof (struct gr_arg));
			memset(grarg, 0, sizeof (struct gr_arg));
			break;
		case 'R':
			if (argc > 2)
				show_help();
			entry.mode = GRADM_RELOAD;
			get_user_passwd(&entry, GR_PWONLY);
			parse_acls();
			expand_acls();
			analyze_acls();
			grarg = conv_user_to_kernel(&entry);
			read_saltandpass(entry.rolename, grarg->salt,
					 grarg->sum);
			transmit_to_kernel(grarg, sizeof (struct gr_arg));
			memset(grarg, 0, sizeof (struct gr_arg));
			break;
		case 'M':
			if ((argc != 3) || (optind > argc)
			    || (strlen(optarg) < 1))
				show_help();
			entry.mode = GRADM_MODSEGV;
			get_user_passwd(&entry, GR_PWONLY);

			if (isdigit(optarg[0]))
				entry.segv_uid = atoi(optarg);
			else
				conv_name_to_num(optarg, &entry.segv_dev,
						 &entry.segv_inode);
			grarg = conv_user_to_kernel(&entry);
			transmit_to_kernel(grarg, sizeof (struct gr_arg));
			memset(grarg, 0, sizeof (struct gr_arg));
			exit(EXIT_SUCCESS);
			break;
		case 'D':
			get_user_passwd(&entry, GR_PWONLY);
			entry.mode = GRADM_DISABLE;
			grarg = conv_user_to_kernel(&entry);
			transmit_to_kernel(grarg, sizeof (struct gr_arg));
			memset(grarg, 0, sizeof (struct gr_arg));
			stop_grlearn();
			exit(EXIT_SUCCESS);
			break;
		case 'L':
			if (argc > 5 || argc < 3)
				show_help();
			gr_learn = 1;
			if (optarg)
				learn_log = strdup(optarg);
			break;
		case 'O':
			if (argc > 5 || argc < 3)
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
				printf("Setting up grsecurity ACL password\n");
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
			get_user_passwd(&entry, GR_PWONLY);
			entry.mode = GRADM_SPROLE;
			grarg = conv_user_to_kernel(&entry);
			transmit_to_kernel(grarg, sizeof (struct gr_arg));
			memset(grarg, 0, sizeof (struct gr_arg));
			exit(EXIT_SUCCESS);
			break;
		case 'n':
			if (argc != 3)
				show_help();
			strncpy(entry.rolename, argv[2], GR_SPROLE_LEN);
			entry.rolename[GR_SPROLE_LEN - 1] = '\0';
			entry.mode = GRADM_SPROLE;
			grarg = conv_user_to_kernel(&entry);
			transmit_to_kernel(grarg, sizeof (struct gr_arg));
			memset(grarg, 0, sizeof (struct gr_arg));
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

	if ((gr_learn && !gr_output) || (gr_output && !gr_learn)) {
		fprintf(stderr, "-L and -O must be used together.\n");
		exit(EXIT_FAILURE);
	}

	if (gr_learn && gr_output) {
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

		handle_learn_logs(learn_log, stream);

	}
	return;
}
