#include "gradm.h"

struct capability_set capability_list[] = {
        { "CAP_CHOWN", CAP_CHOWN},
        { "CAP_DAC_OVERRIDE",CAP_DAC_OVERRIDE},
        { "CAP_DAC_READ_SEARCH",CAP_DAC_READ_SEARCH},
        { "CAP_FOWNER", CAP_FOWNER},
        { "CAP_FSETID", CAP_FSETID},
        { "CAP_KILL", CAP_KILL},
        { "CAP_SETGID", CAP_SETGID},
        { "CAP_SETUID", CAP_SETUID},
        { "CAP_SETPCAP", CAP_SETPCAP},
        { "CAP_LINUX_IMMUTABLE", CAP_LINUX_IMMUTABLE},
        { "CAP_NET_BIND_SERVICE", CAP_NET_BIND_SERVICE},
        { "CAP_NET_BROADCAST", CAP_NET_BROADCAST},
        { "CAP_NET_ADMIN", CAP_NET_ADMIN},
        { "CAP_NET_RAW", CAP_NET_RAW},
        { "CAP_IPC_LOCK", CAP_IPC_LOCK},
        { "CAP_IPC_OWNER", CAP_IPC_OWNER},
        { "CAP_SYS_MODULE", CAP_SYS_MODULE},
        { "CAP_SYS_RAWIO", CAP_SYS_RAWIO},
        { "CAP_SYS_CHROOT", CAP_SYS_CHROOT},
        { "CAP_SYS_PTRACE", CAP_SYS_PTRACE},
        { "CAP_SYS_PACCT", CAP_SYS_PACCT},
        { "CAP_SYS_ADMIN", CAP_SYS_ADMIN},
        { "CAP_SYS_BOOT", CAP_SYS_BOOT},
        { "CAP_SYS_NICE", CAP_SYS_NICE},
        { "CAP_SYS_RESOURCE", CAP_SYS_RESOURCE},
        { "CAP_SYS_TIME", CAP_SYS_TIME},
        { "CAP_SYS_TTY_CONFIG", CAP_SYS_TTY_CONFIG},
        { "CAP_MKNOD", CAP_MKNOD},
        { "CAP_LEASE", CAP_LEASE},
	{ "CAP_ALL", ~0}
};

__u32 cap_conv(const char * cap)
{
	int i;

	for(i=0;i<sizeof(capability_list)/sizeof(struct capability_set);i++)	
		if(!strcmp(cap, capability_list[i].cap_name)) {
			if(i == (sizeof(capability_list)/
				sizeof(struct capability_set) - 1))
				return ~0;  /* CAP_ALL */
			else
				return (1 << (capability_list[i].cap_val));
		}

	fprintf(stderr, "Invalid capability name \"%s\" on line %lu of %s.\n"
                        "The ACL system will not load until this"
                        " error is fixed.\n", cap, lineno, current_acl_file);

	exit(EXIT_FAILURE);

	return 0;
}

void add_cap_acl(struct proc_acl *subject, const char * cap)
{
	__u32 kcap = cap_conv(cap + 1);
	__u32 cap_same;


	if (!subject) {
		fprintf(stderr, "Error on line %lu of %s.  Attempt to "
			"add a capability without a subject declaration.\n"
			"The ACL system will not load until this "
			"error is fixed.\n", lineno, current_acl_file);
		exit(EXIT_FAILURE);
	}

	if(*cap == '+')
		subject->cap_raise |= kcap;
	else
		subject->cap_drop |= kcap;

	cap_same = subject->cap_raise & subject->cap_drop;
	subject->cap_raise &= ~cap_same;
	subject->cap_drop &= ~cap_same;

	return;
}

void modify_caps(struct proc_acl * proc, int cap)
{
	__u32 cap_same;

	proc->cap_raise |= (1 << cap);

	cap_same = proc->cap_raise & proc->cap_drop;
	proc->cap_raise &= ~cap_same;
	proc->cap_drop &= ~cap_same;

	return;
}
