#include "gradm.h"

static struct role_name_table {
	__u16 modeint;
	char modechar;
} role_mode_table[] = {
	{
	GR_ROLE_USER, 'u'}, {
	GR_ROLE_GROUP, 'g'}, {
	GR_ROLE_SPECIAL, 's'}, {
	GR_ROLE_AUTH, 'G'}, {
	GR_ROLE_NOPW, 'N'}, {
	GR_ROLE_GOD, 'A'}, {
	GR_ROLE_TPE, 'T'}
};

static struct mode_name_table {
	__u32 modeint;
	char modechar;
} mode_table[] = {
	{
	GR_READ, 'r'}, {
	GR_EXEC, 'x'}, {
	GR_WRITE, 'w'}, {
	GR_APPEND, 'a'}, {
	GR_INHERIT, 'i'}, {
	GR_PTRACERD, 't'}, {
	GR_SETID,    'm'}, {
	GR_CREATE,    'c'}, {
	GR_DELETE,    'd'}, {
	GR_AUDIT_FIND, 'F'}, {
	GR_AUDIT_READ, 'R'}, {
	GR_AUDIT_WRITE, 'W'}, {
	GR_AUDIT_EXEC, 'X'}, {
	GR_AUDIT_APPEND, 'A'}, {
	GR_AUDIT_INHERIT, 'I'}, {
	GR_AUDIT_SETID, 'M'}, {
	GR_AUDIT_CREATE, 'C'}, {
	GR_AUDIT_DELETE, 'D'}, {
	GR_SUPPRESS, 's'}, {
	GR_FIND, 'h'}
};

static struct subj_mode_name_table {
	__u32 modeint;
	char modechar;
} subj_mode_table[] = {
	{
	GR_OVERRIDE, 'o'}, {
	GR_KILL, 'k'}, {
	GR_PROTECTED, 'p'}, {
	GR_VIEW, 'v'}, {
	GR_IGNORE, 'O'}, {
	GR_FIND, 'h'}, {
	GR_PROTSHM, 'A'}, {
	GR_PAXPAGE, 'P'}, {
	GR_PAXSEGM, 'S'}, {
	GR_PAXRANDMMAP, 'R'}, {
	GR_PAXGCC, 'G'}, {
	GR_PAXMPROTECT, 'M'}, {
	GR_PAXRANDEXEC, 'X'}, {
	GR_KILLPROC, 'K'}, {
	GR_KILLIPPROC, 'C'}, {
	GR_NOTROJAN, 'T'}, {
	GR_PROTPROCFD, 'd'}, {
	GR_PROCACCT, 'b'}
};

void
conv_mode_to_str(__u32 mode, char *modestr, unsigned short len)
{
	unsigned short i;
	unsigned short x;

	memset(modestr, 0, len);

	for (x = 0, i = 0;
	     i < len
	     && x < (sizeof (mode_table) / sizeof (struct mode_name_table));
	     x++) {
		if (mode_table[x].modeint == GR_WRITE && (mode & GR_WRITE)) {
			modestr[i] = 'w';
			mode &= ~GR_APPEND;
			i++;
			continue;
		}
		if (mode_table[x].modeint == GR_AUDIT_WRITE
		    && (mode & GR_AUDIT_WRITE)) {
			modestr[i] = 'W';
			mode &= ~GR_AUDIT_APPEND;
			i++;
			continue;
		}
		if (mode_table[x].modeint == GR_FIND && !(mode & GR_FIND)) {
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

void
conv_subj_mode_to_str(__u32 mode, char *modestr, unsigned short len)
{
	unsigned short i;
	unsigned short x;

	memset(modestr, 0, len);

	for (x = 0, i = 0;
	     i < len
	     && x <
	     (sizeof (subj_mode_table) / sizeof (struct subj_mode_name_table));
	     x++) {
		if (subj_mode_table[x].modeint == GR_FIND && !(mode & GR_FIND)) {
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

void
conv_role_mode_to_str(__u16 mode, char *modestr, unsigned short len)
{
	unsigned short i;
	unsigned short x;

	memset(modestr, 0, len);

	for (x = 0, i = 0;
	     i < len
	     && x <
	     (sizeof (role_mode_table) / sizeof (struct role_name_table));
	     x++) {
		if (mode & role_mode_table[x].modeint) {
			modestr[i] = role_mode_table[x].modechar;
			i++;
		}
	}

	return;
}
