/*
 * Copyright (C) 2002-2014 Bradley Spengler, Open Source Security, Inc.
 *        http://www.grsecurity.net spender@grsecurity.net
 *
 * This file is part of gradm.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include "gradm.h"

const char *rlim_table[GR_NLIMITS];

void init_res_table(void)
{
	rlim_table[RLIMIT_CPU] = "RES_CPU";
	rlim_table[RLIMIT_FSIZE] = "RES_FSIZE";
	rlim_table[RLIMIT_DATA] = "RES_DATA";
	rlim_table[RLIMIT_STACK] = "RES_STACK";
	rlim_table[RLIMIT_CORE] = "RES_CORE";
	rlim_table[RLIMIT_RSS] = "RES_RSS";
	rlim_table[RLIMIT_NPROC] = "RES_NPROC";
	rlim_table[RLIMIT_NOFILE] = "RES_NOFILE";
	rlim_table[RLIMIT_MEMLOCK] = "RES_MEMLOCK";
	rlim_table[RLIMIT_AS] = "RES_AS";
	rlim_table[RLIMIT_LOCKS] = "RES_LOCKS";
	rlim_table[RLIMIT_SIGPENDING] = "RES_SIGPENDING";
	rlim_table[RLIMIT_MSGQUEUE] = "RES_MSGQUEUE";
	rlim_table[RLIMIT_NICE] = "RES_NICE";
	rlim_table[RLIMIT_RTPRIO] = "RES_RTPRIO";
	rlim_table[RLIMIT_RTTIME] = "RES_RTTIME";
	rlim_table[GR_CRASH_RES] = "RES_CRASH";
}

static unsigned short
name_to_res(const char *name)
{
	int i;

	for (i = 0; i < SIZE(rlim_table); i++) {
		if (!rlim_table[i])
			continue;
		if (!strcmp(rlim_table[i], name))
			return i;
	}

	fprintf(stderr, "Invalid resource name: %s "
		"found on line %lu of %s.\n", name, lineno, current_acl_file);
	exit(EXIT_FAILURE);

	return 0;
}

static unsigned int
res_to_mask(unsigned short res)
{
	return (1U << res);
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
		res = res * 60;
		break;
	case 'h':
		res = res * 60 * 60;
		break;
	case 'd':
		res = res * 60 * 60 * 24;
		break;
	case 's':
		//res = res;
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
	if ((res < 0) || (res >= SIZE(rlim_table)))
		return;

	if (proc->resmask & res_to_mask(res)) {
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

	subject->resmask |= res_to_mask(name_to_res(name));

	memcpy(&(subject->res[name_to_res(name)]), &lim, sizeof (lim));

	return;
}
