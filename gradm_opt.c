#include "gradm.h"

static void
expand_acl(struct proc_acl *proc, struct role_acl *role)
{
	char *tmpproc;
	struct proc_acl *tmpp;
	struct file_acl *tmpf1;
	struct file_acl *tmpf2;

	if ((tmpproc =
	     calloc(strlen(proc->filename) + 1, sizeof (char))) == NULL)
		failure("calloc");

	strcpy(tmpproc, proc->filename);

	while (parent_dir(proc->filename, &tmpproc)) {
		for_each_subject(tmpp, role) {
			if (!strcmp(tmpproc, tmpp->filename)) {
				proc->parent_subject = tmpp;
				free(tmpproc);
				return;
			}
		}
	}

	free(tmpproc);
	return;
}

void
expand_acls(void)
{
	struct proc_acl *proc;
	struct role_acl *role;
	struct stat fstat;

	for_each_role(role, current_role) {
		for_each_subject(proc, role) {
			if (!stat(proc->filename, &fstat) && S_ISREG(fstat.st_mode)) {
				if (is_valid_elf_binary(proc->filename)) {
					if (!add_proc_object_acl(proc, proc->filename, proc_object_mode_conv("x"), GR_FLEARN))
						exit(EXIT_FAILURE);
				} else {
					if (!add_proc_object_acl(proc, proc->filename, proc_object_mode_conv("rx"), GR_FLEARN))
						exit(EXIT_FAILURE);
				}
			}
			/* if we're not nested and not /, set parent subject */
			if (!(proc->mode & GR_OVERRIDE) && !(proc->mode & GR_NESTED) && strcmp(proc->filename, "/"))
				expand_acl(proc, role);
		}
	}

	return;
}
