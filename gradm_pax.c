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

struct paxflag_set paxflag_list[] = {
	{"PAX_SEGMEXEC", 0},
	{"PAX_PAGEEXEC", 1},
	{"PAX_MPROTECT", 2},
	{"PAX_RANDMMAP", 3},
	{"PAX_EMUTRAMP", 4}
};

u_int16_t
paxflag_conv(const char *paxflag)
{
	int i;

	for (i = 0; i < sizeof (paxflag_list) / sizeof (struct paxflag_set); i++)
		if (!strcmp(paxflag, paxflag_list[i].paxflag_name))
			return (1U << (paxflag_list[i].paxflag_val));

	fprintf(stderr, "Invalid PaX flag name \"%s\" on line %lu of %s.\n"
		"The RBAC system will not load until this"
		" error is fixed.\n", paxflag, lineno, current_acl_file);

	exit(EXIT_FAILURE);

	return 0;
}

void
add_paxflag_acl(struct proc_acl *subject, const char *paxflag)
{
	u_int16_t kpaxflag = paxflag_conv(paxflag + 1);

	if (!subject) {
		fprintf(stderr, "Error on line %lu of %s.  Attempt to "
			"add a PaX flag without a subject declaration.\n"
			"The RBAC system will not load until this "
			"error is fixed.\n", lineno, current_acl_file);
		exit(EXIT_FAILURE);
	}

	if (*paxflag == '+')
		subject->pax_flags |= kpaxflag;
	else
		subject->pax_flags |= (kpaxflag << 8);

	return;
}

