#include "gradm.h"

/* fix broken glibc installs */
#ifndef RLIMIT_LOCKS
#define RLIMIT_LOCKS 10
#endif
#ifndef NR_OPEN
#define NR_OPEN 1024
#endif

struct rlimconv rlim_table[] = {
	{"RES_CPU", RLIMIT_CPU},
	{"RES_FSIZE", RLIMIT_FSIZE},
	{"RES_DATA", RLIMIT_DATA},
	{"RES_STACK", RLIMIT_STACK},
	{"RES_CORE", RLIMIT_CORE},
	{"RES_RSS", RLIMIT_RSS},
	{"RES_NPROC", RLIMIT_NPROC},
	{"RES_NOFILE", RLIMIT_NOFILE},
	{"RES_MEMLOCK", RLIMIT_MEMLOCK},
	{"RES_AS", RLIMIT_AS},
	{"RES_LOCKS", RLIMIT_LOCKS},
	{"RES_CRASH", RLIMIT_LOCKS + 1}

};

static unsigned short
name_to_res(const char *name)
{
	int i;

	for (i = 0; i < (sizeof (rlim_table) / sizeof (struct rlimconv)); i++) {
		if (!strcmp(rlim_table[i].name, name))
			return rlim_table[i].val;
	}

	fprintf(stderr, "Invalid resource name: %s "
		"found on line %lu of %s.\n", name, lineno, current_acl_file);
	exit(EXIT_FAILURE);

	return 0;
}

static unsigned short
res_to_mask(unsigned short res)
{
	return (1 << res);
}

static unsigned long
conv_res(const char *lim)
{
	unsigned long res;
	char *p;
	int i;
	unsigned int len = strlen(lim);

	if (!strcmp("unlimited", lim))
		return ~0UL;

	if (isdigit(lim[len - 1]))
		return atol(lim);

	if ((p = (char *) calloc(len + 1, sizeof (char))) == NULL)
		failure("calloc");

	strcpy(p, lim);

	for (i = 0; i < len - 1; i++) {
		if (!isdigit(lim[i])) {
			fprintf(stderr, "Invalid resource limit: %s "
				"found on line %lu of %s.\n", lim, lineno,
				current_acl_file);
			exit(EXIT_FAILURE);
		}
	}

	p[i] = '\0';
	res = atol(p);
	free(p);

	switch (lim[i]) {
	case 'm':
		res = res * HZ * 60;
		break;
	case 'h':
		res = res * HZ * 60 * 60;
		break;
	case 'd':
		res = res * HZ * 60 * 60 * 24;
		break;
	case 's':
		res = res * HZ;
		break;
	case 'K':
		res = res << 10;
		break;
	case 'M':
		res = res << 20;
		break;
	case 'G':
		res = res << 30;
		break;
	default:
		fprintf(stderr, "Invalid resource limit: %s "
			"found on line %lu of %s.\n", lim, lineno,
			current_acl_file);
		exit(EXIT_FAILURE);
	}

	return res;
}

void
modify_res(struct proc_acl *proc, int res, unsigned long cur, unsigned long max)
{
	if ((res < 0)
	    || (res > (sizeof (rlim_table) / sizeof (struct rlimconv))))
		return;

	if (proc->resmask & res_to_mask(rlim_table[res].val)) {
		proc->res[res].rlim_cur = cur;
		proc->res[res].rlim_max = max;
	}

	return;
}

void
add_res_acl(struct proc_acl *subject, const char *name,
	    const char *soft, const char *hard)
{
	struct rlimit lim;

	if (!subject) {
		fprintf(stderr, "Error on line %lu of %s.  Attempt to "
			"add a resource without a subject declaration.\n"
			"The RBAC system will not load until this "
			"error is fixed.\n", lineno, current_acl_file);
		exit(EXIT_FAILURE);
	}

	lim.rlim_cur = conv_res(soft);
	lim.rlim_max = conv_res(hard);

	if (!strcmp(name, "RES_NOFILE") && (lim.rlim_cur > NR_OPEN ||
					    lim.rlim_max > NR_OPEN)) {
		fprintf(stderr, "Limits for RES_NOFILE cannot be larger "
			"than %u.\n", NR_OPEN);
		exit(EXIT_FAILURE);
	}

	subject->resmask |= res_to_mask(name_to_res(name));

	memcpy(&(subject->res[name_to_res(name)]), &lim, sizeof (lim));

	return;
}
