#include "gradm.h"

int is_valid_elf_binary(const char * filename)
{
	struct elf32_hdr header_elf;
	int fd;

	if((fd = open(filename, O_RDONLY)) < 0)
		return 0;

	if((read(fd, &header_elf, sizeof(header_elf)) != sizeof(header_elf)))
		goto failure;

	if(strncmp(header_elf.e_ident, ELFMAG, SELFMAG))
		goto failure;
	
	if(header_elf.e_type != ET_EXEC && header_elf.e_type != ET_DYN)
		goto failure;

	close(fd);
	return 1;
failure:
	close(fd);
	return 0;
}

static void find_gradm_path(char * gradm_realpath)
{
	char gradm_procpath[21] = {0};

	snprintf(gradm_procpath, sizeof(gradm_procpath), 
		"/proc/%d/exe", getpid());

	if(readlink(gradm_procpath, gradm_realpath, PATH_MAX - 1) < 0)
		failure("readlink");

	return;
}

void add_gradm_acl(void)
{
	struct stat fstat;	
	char gradm_realpath[PATH_MAX] = {0};
	char * gradm_name;
	struct ip_acl ip;

	find_gradm_path(gradm_realpath);

	gradm_name = strdup(gradm_realpath);
	
	if(!add_proc_subject_acl(current_role, gradm_name, 
			proc_subject_mode_conv("do")))
		exit(EXIT_FAILURE);

	if(!stat("/proc/sys/kernel/grsecurity/acl", &fstat)) {
		if(!add_proc_object_acl(current_subject, 
				"/proc/sys/kernel/grsecurity/acl", proc_object_mode_conv("w"), 0))
			exit(EXIT_FAILURE);
	} else {
		fprintf(stderr, "/proc/sys/kernel/grsecurity/acl does not "
				"exist.  Please recompile your kernel with " 
				"grsecurity's ACL system.\n");
		exit(EXIT_FAILURE);
	}

	memset(&ip, 0, sizeof(ip));
	add_ip_acl(current_subject, GR_IP_CONNECT, &ip);
	add_ip_acl(current_subject, GR_IP_BIND, &ip);

	if(!add_proc_object_acl(current_subject, "/", 
			proc_object_mode_conv("h"), 0))
		exit(EXIT_FAILURE);
	
	if(!add_proc_object_acl(current_subject, gradm_name, 
			proc_object_mode_conv("x"), 0))
		exit(EXIT_FAILURE);
	add_cap_acl(current_subject, "-CAP_ALL");

	return;
}

void add_admin_acl(void)
{
	if(!add_proc_subject_acl(current_role, "god", proc_subject_mode_conv("kvo")))
		exit(EXIT_FAILURE);
	if(!add_proc_object_acl(current_subject, "/", proc_object_mode_conv("rwxi"), 0))
		exit(EXIT_FAILURE);
	add_cap_acl(current_subject, "+CAP_ALL");

	return;
}	

void add_kernel_acl(void)
{
	if(!add_proc_subject_acl(current_role, "kernel", proc_subject_mode_conv("o")))
		exit(EXIT_FAILURE);
	if(!add_proc_object_acl(current_subject, "/", proc_object_mode_conv(""), 0))
		exit(EXIT_FAILURE);
	if(!add_proc_object_acl(current_subject, "/bin/true", proc_object_mode_conv("x"), 0))
		exit(EXIT_FAILURE);
	if(!add_proc_object_acl(current_subject, "/sbin/hotplug", proc_object_mode_conv("rx"), 0))
		exit(EXIT_FAILURE);
	if(!add_proc_object_acl(current_subject, "/sbin/modprobe", proc_object_mode_conv("x"), 0))
		exit(EXIT_FAILURE);

	return;
}	
