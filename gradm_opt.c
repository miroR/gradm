#include "gradm.h"

static void compute_cap_creds(struct proc_acl * set, struct proc_acl * cmp)
{
	__u32 cap_same;

	set->cap_raise |= cmp->cap_raise;
	set->cap_drop |= cmp->cap_drop;

	cap_same = set->cap_raise & cmp->cap_drop;
	set->cap_raise &= ~cap_same;
	set->cap_drop &= ~cap_same;
	cap_same = set->cap_drop & cmp->cap_raise;
	set->cap_drop &= ~cap_same;
	set->cap_raise &= ~cap_same;

	return;
}

static void expand_acl(struct proc_acl * proc)
{
	char * tmpproc;
	struct role_acl * tmpr;
	struct proc_acl * tmpp;
	struct file_acl * tmpf1;
	struct file_acl * tmpf2;

	if((tmpproc = calloc(strlen(proc->filename) + 1, sizeof(char))) == NULL)
		failure("calloc");

	strncpy(tmpproc,proc->filename,strlen(proc->filename));

	for_each_role(tmpr, current_role) {
	while(parent_dir(proc->filename, &tmpproc)) {
	 for_each_subject(tmpp, tmpr) {
	  if(!strcmp(tmpproc,tmpp->filename)) {
	   compute_cap_creds(proc, tmpp);  // perform capability inheritance
	   for_each_object(tmpf1, tmpp->proc_object) {
	    for_each_object(tmpf2, proc->proc_object)
	     if(!strcmp(tmpf1->filename, tmpf2->filename))
	      break;
	    if(!tmpf2) // object not found in current subject
	     add_proc_object_acl(proc, tmpf1->filename, tmpf1->mode, GR_FEXIST);
	   }
	  }
	 }
	}
	}

	free(tmpproc);
	return;
}

void expand_acls(void)
{
	struct proc_acl * proc;
	struct role_acl * role;

	for_each_role(role, current_role) {
		for_each_subject(proc, role) {
			if(!(proc->mode & GR_OVERRIDE))
				expand_acl(proc);
			else
				proc->mode &= ~GR_OVERRIDE;
		}
	}

	return;
}
