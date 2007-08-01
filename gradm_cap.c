#include "gradm.h"

struct capability_set capability_list[] = {
	{"CAP_CHOWN", 0},
	{"CAP_DAC_OVERRIDE", 1},
	{"CAP_DAC_READ_SEARCH", 2},
	{"CAP_FOWNER", 3},
	{"CAP_FSETID", 4},
	{"CAP_KILL", 5},
	{"CAP_SETGID", 6},
	{"CAP_SETUID", 7},
	{"CAP_SETPCAP", 8},
	{"CAP_LINUX_IMMUTABLE", 9},
	{"CAP_NET_BIND_SERVICE", 10},
	{"CAP_NET_BROADCAST", 11},
	{"CAP_NET_ADMIN", 12},
	{"CAP_NET_RAW", 13},
	{"CAP_IPC_LOCK", 14},
	{"CAP_IPC_OWNER", 15},
	{"CAP_SYS_MODULE", 16},
	{"CAP_SYS_RAWIO", 17},
	{"CAP_SYS_CHROOT", 18},
	{"CAP_SYS_PTRACE", 19},
	{"CAP_SYS_PACCT", 20},
	{"CAP_SYS_ADMIN", 21},
	{"CAP_SYS_BOOT", 22},
	{"CAP_SYS_NICE", 23},
	{"CAP_SYS_RESOURCE", 24},
	{"CAP_SYS_TIME", 25},
	{"CAP_SYS_TTY_CONFIG", 26},
	{"CAP_MKNOD", 27},
	{"CAP_LEASE", 28},
	{"CAP_AUDIT_WRITE", 29},
	{"CAP_AUDIT_CONTROL", 30},
	{"CAP_ALL", ~0}
};

u_int32_t
cap_conv(const char *cap)
{
	int i;

	for (i = 0;
	     i < sizeof (capability_list) / sizeof (struct capability_set); i++)
		if (!strcmp(cap, capability_list[i].cap_name)) {
			if (i == (sizeof (capability_list) /
				  sizeof (struct capability_set) - 1))
				return ~0;	/* CAP_ALL */
			else
				return (1 << (capability_list[i].cap_val));
		}

	fprintf(stderr, "Invalid capability name \"%s\" on line %lu of %s.\n"
		"The RBAC system will not load until this"
		" error is fixed.\n", cap, lineno, current_acl_file);

	exit(EXIT_FAILURE);

	return 0;
}

void
add_cap_acl(struct proc_acl *subject, const char *cap)
{
	u_int32_t kcap = cap_conv(cap + 1);

	if (!subject) {
		fprintf(stderr, "Error on line %lu of %s.  Attempt to "
			"add a capability without a subject declaration.\n"
			"The RBAC system will not load until this "
			"error is fixed.\n", lineno, current_acl_file);
		exit(EXIT_FAILURE);
	}

	if (*cap == '+') {
		subject->cap_drop &= ~kcap;
		subject->cap_mask |= kcap;
	} else {
		subject->cap_drop |= kcap;
		subject->cap_mask |= kcap;
	}
	return;
}

void
modify_caps(struct proc_acl *proc, int cap)
{
	proc->cap_drop &= ~(1 << cap);
	proc->cap_mask |= (1 << cap);

	return;
}
