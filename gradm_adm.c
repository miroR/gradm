#include "gradm.h"

int
is_valid_elf_binary(const char *filename)
{
	Elf32_Ehdr header_elf;
	Elf64_Ehdr header_elf64;
	int fd;

	if ((fd = open(filename, O_RDONLY)) < 0)
		return 0;

	if ((read(fd, &header_elf64, sizeof (header_elf64)) != sizeof (header_elf64)))
		goto failure;

	memcpy(&header_elf, &header_elf64, sizeof(header_elf));

	/* binary is 32bit */
	if (header_elf.e_ident[EI_CLASS] == 1) {
		if (strncmp(header_elf.e_ident, ELFMAG, SELFMAG))
			goto failure;

		if (header_elf.e_type != ET_EXEC && header_elf.e_type != ET_DYN)
			goto failure;
	/* binary is 64bit */
	} else if (header_elf64.e_ident[EI_CLASS] == 2) {
		if (strncmp(header_elf64.e_ident, ELFMAG, SELFMAG))
			goto failure;

		if (header_elf64.e_type != ET_EXEC && header_elf64.e_type != ET_DYN)
			goto failure;

	} else
		goto failure;

	close(fd);
	return 1;
      failure:
	close(fd);
	return 0;
}

static void
find_gradm_path(char *gradm_realpath)
{
	char gradm_procpath[21] = { 0 };

	snprintf(gradm_procpath, sizeof (gradm_procpath),
		 "/proc/%d/exe", getpid());

	if (readlink(gradm_procpath, gradm_realpath, PATH_MAX - 1) < 0)
		failure("readlink");

	return;
}

void
add_gradm_acl(struct role_acl *role)
{
	struct stat fstat;
	char gradm_realpath[PATH_MAX] = { 0 };
	char *gradm_name;
	struct ip_acl ip;

	find_gradm_path(gradm_realpath);

	gradm_name = strdup(gradm_realpath);

	if (!add_proc_subject_acl(role, gradm_name,
				  proc_subject_mode_conv("do"), 0))
		exit(EXIT_FAILURE);

	if (!stat(GRDEV_PATH, &fstat)) {
		if (!add_proc_object_acl(current_subject, GRDEV_PATH,
					 proc_object_mode_conv("w"), GR_FEXIST))
			exit(EXIT_FAILURE);
	} else {
		fprintf(stderr, "%s does not "
			"exist.  Please recompile your kernel with "
			"grsecurity and install a newer version of gradm.\n",
			GRDEV_PATH);
		exit(EXIT_FAILURE);
	}

	memset(&ip, 0, sizeof (ip));
	add_ip_acl(current_subject, GR_IP_CONNECT, &ip);
	add_ip_acl(current_subject, GR_IP_BIND, &ip);

	if (!add_proc_object_acl(current_subject, "/",
				 proc_object_mode_conv("h"), GR_FEXIST))
		exit(EXIT_FAILURE);

	if (!add_proc_object_acl(current_subject, "/etc/ld.so.cache",
				 proc_object_mode_conv("r"), GR_FEXIST))
		exit(EXIT_FAILURE);

	if (!add_proc_object_acl(current_subject, "/etc/ld.so.preload",
				 proc_object_mode_conv("r"), GR_FEXIST))
		exit(EXIT_FAILURE);

	if (!add_proc_object_acl(current_subject, "/dev/urandom",
				 proc_object_mode_conv("r"), GR_FEXIST))
		exit(EXIT_FAILURE);

	if (!add_proc_object_acl(current_subject, "/lib",
				 proc_object_mode_conv("rx"), GR_FEXIST))
		exit(EXIT_FAILURE);

	if (!add_proc_object_acl(current_subject, "/usr/lib",
				 proc_object_mode_conv("rx"), GR_FEXIST))
		exit(EXIT_FAILURE);

	if (!add_proc_object_acl(current_subject, "/lib64",
				 proc_object_mode_conv("rx"), GR_FEXIST))
		exit(EXIT_FAILURE);

	if (!add_proc_object_acl(current_subject, "/usr/lib64",
				 proc_object_mode_conv("rx"), GR_FEXIST))
		exit(EXIT_FAILURE);

	if (!add_proc_object_acl(current_subject, gradm_name,
				 proc_object_mode_conv("x"), GR_FEXIST))
		exit(EXIT_FAILURE);
	add_cap_acl(current_subject, "-CAP_ALL");
	add_cap_acl(current_subject, "+CAP_IPC_LOCK");

	return;
}

void
add_kernel_acl(void)
{
	if (!add_role_acl
	    (&current_role, strdup(":::kernel:::"), role_mode_conv("sN"), 1))
		exit(EXIT_FAILURE);
	if (!add_proc_subject_acl
	    (current_role, "/", proc_subject_mode_conv("o"), 0))
		exit(EXIT_FAILURE);
	if (!add_proc_object_acl
	    (current_subject, "/", proc_object_mode_conv("rx"), GR_FEXIST))
		exit(EXIT_FAILURE);
	if (!add_proc_object_acl
	    (current_subject, "/dev/tty", proc_object_mode_conv("rw"), GR_FEXIST))
		exit(EXIT_FAILURE);
	if (!add_proc_object_acl
	    (current_subject, "/dev/null", proc_object_mode_conv("rw"), GR_FEXIST))
		exit(EXIT_FAILURE);
	if (!add_proc_object_acl
	    (current_subject, "/etc/grsec", proc_object_mode_conv("h"),
	     GR_FEXIST))
		exit(EXIT_FAILURE);

	return;
}

void
add_grlearn_acl(struct role_acl *role)
{
	struct stat fstat;
	struct ip_acl ip;

	if (stat(GRLEARN_PATH, &fstat)) {
		fprintf(stderr, "%s does not exist.  Please reinstall gradm.\n", GRLEARN_PATH);
		exit(EXIT_FAILURE);
	}

	if (!add_proc_subject_acl(role, GRLEARN_PATH,
				  proc_subject_mode_conv("hpdo"), 0))
		exit(EXIT_FAILURE);

	memset(&ip, 0, sizeof (ip));
	add_ip_acl(current_subject, GR_IP_CONNECT, &ip);
	add_ip_acl(current_subject, GR_IP_BIND, &ip);

	if (!add_proc_object_acl(current_subject, "/",
				 proc_object_mode_conv("h"), GR_FEXIST))
		exit(EXIT_FAILURE);

	if (!add_proc_object_acl(current_subject, GRLEARN_PATH,
				 proc_object_mode_conv("x"), GR_FEXIST))
		exit(EXIT_FAILURE);
	add_cap_acl(current_subject, "-CAP_ALL");

	return;
}

void add_fulllearn_acl(void)
{
	struct ip_acl ip;

	if (!add_role_acl
	    (&current_role, strdup("default"), role_mode_conv("A"), 0))
		exit(EXIT_FAILURE);
	if (!add_proc_subject_acl
	    (current_role, "/", proc_subject_mode_conv("ol"), 0))
		exit(EXIT_FAILURE);
	if (!add_proc_object_acl
	    (current_subject, "/", proc_object_mode_conv("h"), GR_FEXIST))
		exit(EXIT_FAILURE);
	add_cap_acl(current_subject, "-CAP_ALL");

	memset(&ip, 0, sizeof (ip));
	add_ip_acl(current_subject, GR_IP_CONNECT, &ip);
	add_ip_acl(current_subject, GR_IP_BIND, &ip);
	add_gradm_acl(current_role);
	add_kernel_acl();
	expand_acls();
	return;
}

void add_rolelearn_acl(void)
{
	struct ip_acl ip;

	if (!add_proc_subject_acl
	    (current_role, "/", proc_subject_mode_conv("ol"), 0))
		exit(EXIT_FAILURE);
	if (!add_proc_object_acl
	    (current_subject, "/", proc_object_mode_conv("h"), GR_FEXIST))
		exit(EXIT_FAILURE);
	add_cap_acl(current_subject, "-CAP_ALL");

	memset(&ip, 0, sizeof (ip));
	add_ip_acl(current_subject, GR_IP_CONNECT, &ip);
	add_ip_acl(current_subject, GR_IP_BIND, &ip);

	return;
}

void start_grlearn(char *logfile)
{
	pid_t pid;

	pid = fork();

	if (!pid) {
		execl(GRLEARN_PATH, GRLEARN_PATH, logfile, NULL);
	} else if (pid > 0) {
		wait(NULL);
	}

	return;
}

void stop_grlearn(void)
{
	pid_t pid;

	pid = fork();

	if (!pid) {
		execl(GRLEARN_PATH, GRLEARN_PATH, "-stop", NULL);
	}

	return;
}
