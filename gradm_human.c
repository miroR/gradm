#include "gradm.h"

static struct mode_name_table {
	__u32 modeint;
	char modechar;
} mode_table[] = {
	{ GR_READ, 'r' },
	{ GR_EXEC, 'x' },
	{ GR_WRITE, 'w' },
	{ GR_APPEND, 'a' },
	{ GR_INHERIT, 'i' },
	{ GR_PTRACERD, 't' },
	{ GR_AUDIT_FIND, 'F' },
	{ GR_AUDIT_READ, 'R' },
	{ GR_AUDIT_WRITE, 'W' },
	{ GR_AUDIT_EXEC, 'X' },
	{ GR_AUDIT_APPEND, 'A' },
	{ GR_AUDIT_INHERIT, 'I' },
	{ GR_AUDIT_PTRACERD, 'T' },
	{ GR_FIND, 'h' }
};

static struct subj_mode_name_table {
	__u32 modeint;
	char modechar;
} subj_mode_table[] = {
	{ GR_KILL, 'k' },
	{ GR_PROTECTED, 'p' },
	{ GR_VIEW, 'v' },
	{ GR_IGNORE, 'O' },
	{ GR_FIND, 'h' },
	{ GR_PROTSHM, 'A' },
	{ GR_PAXPAGE, 'P' },
	{ GR_PAXSEGM, 'S' },
	{ GR_PAXRANDMMAP, 'R' },
	{ GR_PAXGCC, 'G' },
	{ GR_PAXMPROTECT, 'M' },
	{ GR_PAXRANDEXEC, 'X' },
	{ GR_KILLPROC, 'K' },
	{ GR_KILLIPPROC, 'C' },
	{ GR_NOTROJAN, 'T' },
	{ GR_PROTPROCPID, 'd' }
};
	
static int netmask_to_int(unsigned long netmask)
{
	unsigned short i;
	unsigned long net;

	if(!netmask) return 0;

	if(netmask == 0xffffffff) return 32;

	for(i = 0; i <= 32; i++) {
		net = 0xffffffff << (32 - i);
		if(net == netmask) return i;
	}

	return 0;
}

static void show_ip_acl(struct ip_acl * ipp, FILE * stream)
{
	struct in_addr addr;
	unsigned short netmask;
	unsigned short i;
	struct protoent * proto;

	addr.s_addr = ipp->addr;
	netmask = netmask_to_int(ipp->netmask);

	if((netmask == 32) && ipp->low == ipp->high)
		fprintf(stream, "\t\t%s:%u", inet_ntoa(addr), ipp->low);
	else if(ipp->low == ipp->high)
		fprintf(stream, "\t\t%s/%u:%u", inet_ntoa(addr), 
				netmask, ipp->low);
	else if(netmask == 32)
		fprintf(stream, "\t\t%s:%u-%u", inet_ntoa(addr), 
				ipp->low, ipp->high);
	else
		fprintf(stream, "\t\t%s/%u:%u-%u", inet_ntoa(addr), 
				netmask, ipp->low, ipp->high);

	for(i = 1; i < 5; i++) {
		if(ipp->type & (1 << i)) {
			switch(i) {
			case SOCK_RAW: fprintf(stream, " raw_sock"); break;
			case SOCK_DGRAM: fprintf(stream, " dgram"); break;
			case SOCK_STREAM: fprintf(stream, " stream"); break;
			case SOCK_RDM: fprintf(stream, " rdm"); break;
			}
		}
	}
	for(i = 0; i < 256; i++) {
		if(ipp->proto[i / 32] & (1 << (i % 32))) {
			if(i == IPPROTO_RAW) {
				fprintf(stream, " raw_proto");
			} else {
				proto = getprotobynumber(i);
				fprintf(stream, " %s", proto->p_name);
			}
		}
	}

	fprintf(stream, "\n");
	return;
}

static void conv_mode_to_str(__u32 mode, char * modestr, unsigned short len)
{
	unsigned short i;
	unsigned short x;

	memset(modestr, 0, len);

	for(x = 0, i = 0; i < len && x < (sizeof(mode_table)/sizeof(struct mode_name_table)); x++) {
		if(mode_table[x].modeint == GR_WRITE && (mode & GR_WRITE)) {
			modestr[i] = 'w';
			mode &= ~GR_APPEND;
			i++;
			continue;
		}
		if(mode_table[x].modeint == GR_AUDIT_WRITE && (mode & GR_AUDIT_WRITE)) {
			modestr[i] = 'W';
			mode &= ~GR_AUDIT_APPEND;
			i++;
			continue;
		}
		if(mode_table[x].modeint == GR_FIND && !(mode & GR_FIND)) {
			modestr[i] = 'h';
			i++;
			continue;
		} else if (mode_table[x].modeint == GR_FIND)
			continue;

		if (mode & mode_table[x].modeint) {
			modestr[i] = mode_table[x].modechar;
			i++;
		}
	}

	return;
}

static void conv_subj_mode_to_str(__u32 mode, char * modestr, unsigned short len)
{
	unsigned short i;
	unsigned short x;

	memset(modestr, 0, len);

	for(x = 0, i = 0; i < len && x < (sizeof(subj_mode_table)/sizeof(struct subj_mode_name_table)); x++) {
		if(subj_mode_table[x].modeint == GR_FIND && !(mode & GR_FIND)) {
			modestr[i] = 'h';
			i++;
			continue;
		} else if (subj_mode_table[x].modeint == GR_FIND)
			continue;

		if (mode & subj_mode_table[x].modeint) {
			modestr[i] = subj_mode_table[x].modechar;
			i++;
		}
	}

	return;
}

void pass_struct_to_human(FILE * stream)
{
	unsigned short i;
	char modes[7];
	struct role_acl * role;
	struct proc_acl * proc;
	struct file_acl * filp;	
	struct ip_acl * ipp;
	unsigned int drop_num;
	unsigned long c_cnt;
	unsigned long b_cnt;

	for_each_role(role, current_role) {
	for_each_subject(proc, role) {
		if(!(proc->mode & GR_LEARN)) continue;
		proc->mode &= ~GR_LEARN;
		conv_subj_mode_to_str(proc->mode,
				modes, sizeof(modes));
		fprintf(stream, "%s %so {\n", proc->filename, modes); 
		for_each_object(filp, proc->proc_object) {
			conv_mode_to_str(filp->mode,
				modes, sizeof(modes));
			fprintf(stream, "\t%s %s\n",filp->filename, modes);	
		}

		for(i = drop_num = 0; i < ((sizeof(capability_list)/sizeof(struct capability_set)) - 1); i++)
			if(proc->cap_drop & (1 << capability_list[i].cap_val))
				drop_num++;

		if(!drop_num)
			fprintf(stream, "\t+CAP_ALL\n");
		else if(drop_num == ((sizeof(capability_list)/sizeof(struct capability_set)) - 1))
			fprintf(stream, "\t-CAP_ALL\n");
		else if(drop_num < ((sizeof(capability_list)/sizeof(struct capability_set)) - 1)/2) {
			fprintf(stream, "\t+CAP_ALL\n");
			for(i = 0; i < ((sizeof(capability_list)/sizeof(struct capability_set)) - 1); i++)
				if(proc->cap_drop & (1 << capability_list[i].cap_val))
						fprintf(stream, "\t-%s\n", 
							capability_list[i].cap_name);
		} else {
			fprintf(stream, "\t-CAP_ALL\n");
			for(i = 0; i < ((sizeof(capability_list)/sizeof(struct capability_set)) - 1); i++)
				if(!(proc->cap_drop & (1 << capability_list[i].cap_val)))
						fprintf(stream, "\t+%s\n", 
							capability_list[i].cap_name);
		}

		for(i = 0; i < (sizeof(rlim_table)/sizeof(struct rlimconv)); i++)
			if(proc->resmask & (1 << rlim_table[i].val))
				fprintf(stream, "\t%s %lu %lu\n", 
					rlim_table[i].name, 
					proc->res[i].rlim_cur, 
					proc->res[i].rlim_max);
		if(!proc->ip_object)
			goto finish_acl;

		c_cnt = 0;
		b_cnt = 0;

		for_each_object(ipp, proc->ip_object) {
			if(ipp->mode == GR_IP_CONNECT)
				c_cnt++;
			else if(ipp->mode == GR_IP_BIND)
				b_cnt++;			
		}

		fprintf(stream, "\n\tconnect {\n");
		for_each_object(ipp, proc->ip_object) {
			if(ipp->mode == GR_IP_CONNECT) {
				if(c_cnt == 1 && !ipp->type)
					fprintf(stream, "\t\tdisabled\n");
				else if(ipp->type)
					show_ip_acl(ipp, stream);
			}
		}

		fprintf(stream, "\t}\n\n");		
		fprintf(stream, "\tbind {\n");
		for_each_object(ipp, proc->ip_object) {
			if(ipp->mode == GR_IP_BIND) {
				if(b_cnt == 1 && !ipp->type)
					fprintf(stream, "\t\tdisabled\n");
				else if(ipp->type)
					show_ip_acl(ipp, stream);
			}
		}

		fprintf(stream, "\t}\n\n");		
finish_acl:
		fprintf(stream, "}\n");
	}
	}

	return;
}
