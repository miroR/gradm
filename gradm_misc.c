#include "gradm.h"

FILE *
open_acl_file(const char *filename)
{
	FILE *aclfile;

	if ((aclfile = fopen(filename, "r")) == NULL) {
		fprintf(stderr, "Unable to open %s for reading.\n", filename);
		failure("fopen");
	}

	return aclfile;
}

int
transmit_to_kernel(struct gr_arg *buf)
{
	int fd;
	int err = 0;
	void *pbuf = buf;

	if ((fd = open(GRDEV_PATH, O_WRONLY)) < 0) {
		fprintf(stderr, "Could not open %s.\n", GRDEV_PATH);
		failure("open");
	}

	if (write(fd, &pbuf, sizeof(struct gr_arg *)) != sizeof(struct gr_arg *)) {
		err = 1;
		switch (errno) {
		case EFAULT:
			fprintf(stderr, "Error copying structures to the "
				"kernel.\n");
			break;
		case ENOMEM:
			fprintf(stderr, "Out of memory.\n");
			break;
		case EBUSY:
			fprintf(stderr, "You have attempted to authenticate "
				"while authentication was locked, try "
				"again later.\n");
			break;
		case EAGAIN:
			fprintf(stderr, "Your request was ignored, "
				"please check the kernel logs for more "
				"info.\n");
		case EPERM:
			fprintf(stderr, "Invalid password.\n");
			break;
		case EINVAL:
		default:
			fprintf(stderr, "You are using incompatible "
				"versions of gradm and grsecurity.\n"
				"Please update both versions to the "
				"ones available on the website.\n");
		}
	}

	close(fd);

	return err;
}

void check_acl_status(__u16 reqmode)
{
	int fd;
	int retval;
	struct gr_arg arg;
	struct gr_arg *parg = arg;

	arg.mode = GRADM_STATUS;

	if ((fd = open(GRDEV_PATH, O_WRONLY)) < 0) {
		fprintf(stderr, "Could not open %s.\n", GRDEV_PATH);
		failure("open");
	}

	retval = write(fd, &parg, sizeof(struct gr_arg *));
	close(fd);

	switch (reqmode) {
	case GRADM_STATUS:
		if (retval == 1) {
			printf("The RBAC system is currently enabled.\n");
			exit(0);
		} else if (retval == 2) {
			printf("The RBAC system is currently disabled.\n");
			exit(1);
		}
		break;
	case GRADM_ENABLE:
		if (retval == 1) {
			printf("The operation you requested cannot be performed "
				"because the RBAC system is currently enabled.\n");
			exit(EXIT_FAILURE);
		}
		break;
	case GRADM_RELOAD:
	case GRADM_DISABLE:
	case GRADM_SPROLE:
	case GRADM_UNSPROLE:
	case GRADM_MODSEGV:
		if (retval == 2) {
			printf("The operation you requested cannot be performed "
				"because the RBAC system is currently disabled.\n");
			exit(EXIT_FAILURE);
		}
		break;
	}

	return;
}

void
init_variables(void)
{
	extern struct ip_acl ip;
	lineno = 1;

	current_acl_file = NULL;
	current_role = NULL;
	current_subject = NULL;

	memset(&ip, 0, sizeof (ip));

	return;
}

void
change_current_acl_file(const char *filename)
{
	char *p;

	if ((p = (char *) calloc(strlen(filename) + 1, sizeof (char))) == NULL)
		failure("calloc");

	strcpy(p, filename);

	current_acl_file = p;

	return;
}

int
parent_dir(const char *filename, char *parent_dirent[])
{
	int i;

	if ((strlen(*parent_dirent) <= 1) || (strlen(filename) <= 1))
		return 0;

	for (i = strlen(*parent_dirent) - 1; i >= 0; i--) {
		if (i)
			(*parent_dirent)[i] = '\0';
		if (filename[i] == '/')
			return 1;
	}

	return 0;
}
