/*
 * Copyright (C) 2002-2016 Bradley Spengler, Open Source Security, Inc.
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

void
add_proc_nested_acl(struct role_acl *role, const char *mainsubjname,
		    const char * const *nestednames, int nestlen, u_int32_t nestmode)
{
	int i;
	char *nestname;
	unsigned int namelen = 0;
	struct proc_acl *stmp;
	struct file_acl *otmp = NULL;
	struct stat fstat;

	if (nestmode & GR_LEARN) {
		fprintf(stderr, "Error on line %lu of %s:\n", lineno,
			current_acl_file);
		fprintf(stderr,
			"Learning is not yet implemented for nested subjects.\n");
		exit(EXIT_FAILURE);
	}

	namelen += strlen(mainsubjname);
	for (i = 0; i < nestlen; i++)
		namelen += strlen(nestednames[i]) + 1;

	nestname = (char *)gr_alloc(namelen + 1);
	strcpy(nestname, mainsubjname);
	for (i = 0; i < nestlen; i++)
		sprintf(nestname + strlen(nestname), ":%s", nestednames[i]);

	stmp = lookup_acl_subject_by_name(role, mainsubjname);
	if (stmp == NULL) {
		fprintf(stderr,
			"No subject %s found for nested subject %s specified on line %lu of %s.\n",
			mainsubjname, nestname, lineno, current_acl_file);
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < nestlen; i++) {
		otmp = lookup_acl_object_by_name(stmp, nestednames[i]);
		if (otmp == NULL) {
			fprintf(stderr,
				"No object %s found for nested subject %s "
				"specified on line %lu of %s.\n",
				nestednames[i], nestname, lineno,
				current_acl_file);
			exit(EXIT_FAILURE);
		} else if (!otmp->nested && (i != nestlen - 1)) {
			fprintf(stderr,
				"No nested subject %s found for nested "
				"subject %s specified on line %lu of %s.\n",
				nestednames[i], nestname, lineno,
				current_acl_file);
			exit(EXIT_FAILURE);
		} else if (otmp->nested && (i == nestlen - 1)) {
			fprintf(stderr,
				"Duplicate nested subject %s found on line "
				"%lu of %s.\n",
				nestname, lineno, current_acl_file);
			exit(EXIT_FAILURE);
		}
		if (i != nestlen - 1)
			stmp = otmp->nested;
	}

	add_proc_subject_acl(role, nestednames[i - 1], nestmode, GR_FFAKE);

	namelen = strlen(nestednames[i-1]);
	for_each_file_object(otmp, stmp) {
		if (!strncmp(nestednames[i-1], otmp->filename, namelen) && (otmp->filename[namelen] == '/' || otmp->filename[namelen] == '\0'))
			if (otmp->mode & GR_EXEC)
				otmp->nested = current_subject;
	}
	if (!(current_subject->mode & GR_OVERRIDE) && strcmp(current_subject->filename, "/"))
		current_subject->parent_subject = stmp;

	if (!stat(nestednames[i - 1], &fstat) && S_ISREG(fstat.st_mode))
		add_proc_object_acl(current_subject, nestednames[i - 1], proc_object_mode_conv("rx"), GR_FLEARN);

	return;
}
