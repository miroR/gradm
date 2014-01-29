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

static void
expand_acl(struct proc_acl *proc, struct role_acl *role)
{
	char *tmpproc;
	struct proc_acl *tmpp;

	tmpproc = (char *)alloca(strlen(proc->filename) + 1);
	strcpy(tmpproc, proc->filename);

	while (parent_dir(proc->filename, &tmpproc)) {
		tmpp = lookup_acl_subject_by_name(role, tmpproc);
	        if (tmpp) {
			proc->parent_subject = tmpp;
			return;
		}
	}

	return;
}

static void
expand_socket_families(struct proc_acl *proc)
{
	/* set up the socket families
	   if proc->ips != NULL, then some connect/bind
	   rules were specified
	   we default to allowing unix/ipv4 sockets
	   if any connect/bind rules are specified
	*/
	if (proc->ips != NULL) {
		add_sock_family(proc, "unix");
		add_sock_family(proc, "ipv4");
	} else if (!proc->sock_families[0] &&
		   !proc->sock_families[1]) {
	/* there are no connect/bind rules and no
	   socket_family rules, so we must allow
	   all families
	*/
		add_sock_family(proc, "all");
	}
}

void
expand_acls(void)
{
	struct proc_acl *proc;
	struct role_acl *role;
	struct stat fstat;

	/* handle expansion of nested subjects */
	for_each_nested_subject(proc) {
		expand_socket_families(proc);
	}

	/* handle expansion of all non-nested subjects */
	for_each_role(role, current_role) {
		for_each_subject(proc, role) {
			expand_socket_families(proc);

			/* add an object into each non-dir subject that allows it to read/exec itself
			   for nested subjects this is handled in gradm_nest.c */
			if (!lstat(proc->filename, &fstat)) {
				char buf[PATH_MAX] = {0};
				if (S_ISLNK(fstat.st_mode)) {
					readlink(proc->filename, buf, sizeof(buf) - 1);
					if (!lstat(buf, &fstat) && S_ISREG(fstat.st_mode)) {
						add_proc_object_acl(proc, gr_strdup(buf), proc_object_mode_conv("rx"), GR_FLEARN);
					}
				} else if (S_ISREG(fstat.st_mode)) {
					add_proc_object_acl(proc, gr_strdup(proc->filename), proc_object_mode_conv("rx"), GR_FLEARN);
				}
			}
			/* if we're not /, set parent subject
			   setting the parent subject for nested subjects is handled
			   in gradm_nest.c when creating the subject
			 */
			if (!(proc->mode & GR_OVERRIDE) && strcmp(proc->filename, "/"))
				expand_acl(proc, role);
		}
	}

	return;
}
