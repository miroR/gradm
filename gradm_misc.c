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
transmit_to_kernel(void *buf, unsigned long len)
{
	int fd;
	int err = 0;

	if ((fd = open("/dev/grsec", O_WRONLY)) < 0) {
		fprintf(stderr, "Could not open /dev/grsec.\n");
		failure("open");
	}

	if (write(fd, buf, len) != len) {
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

	strncpy(p, filename, strlen(filename));

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
