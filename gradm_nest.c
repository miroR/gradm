#include "gradm.h"

void
add_proc_nested_acl(struct role_acl *role, char *mainsubjname,
		    char **nestednames, int nestlen, __u32 nestmode)
{
	int i;
	char *nestname;
	unsigned int namelen = 0;
	struct role_acl *rtmp;
	struct proc_acl *stmp;
	struct file_acl *otmp;

	int subj_found = 0;
	int nest_found = 0;

	if ((nestmode & GR_LEARN) || !(nestmode & GR_OVERRIDE)) {
		fprintf(stderr, "Error on line %lu of %s:\n", lineno,
			current_acl_file);
		fprintf(stderr,
			"Learning is not yet implemented for nested subjects, "
			"and nested subjects must have \"o\" in their mode.\n");
		exit(EXIT_FAILURE);
	}

	namelen += strlen(mainsubjname);
	for (i = 0; i < nestlen; i++)
		namelen += strlen(nestednames[i]) + 1;

	nestname = malloc(nestlen + 1);

	if (!nestname) {
		fprintf(stderr, "Out of memory.\n");
		exit(EXIT_FAILURE);
	}

	strcpy(nestname, mainsubjname);
	for (i = 0; i < nestlen; i++)
		sprintf(nestname + strlen(nestname), ":%s", nestednames[i]);

	for_each_subject(stmp, role) {
		if (!strcmp(mainsubjname, stmp->filename)) {
			subj_found = 1;
			break;
		}
	}

	if (!subj_found) {
		fprintf(stderr,
			"No subject %s found for nested subject %s specified on line %lu of %s.\n",
			mainsubjname, nestname, lineno, current_acl_file);
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < nestlen; i++) {
		nest_found = 0;
		for_each_object(otmp, stmp->proc_object) {
			if (!strcmp(nestednames[i], otmp->filename)) {
				nest_found = 1;
				break;
			}
		}
		if (!nest_found) {
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
		stmp = otmp->nested;
	}

	add_proc_subject_acl(role, nestednames[i - 1], nestmode, GR_FFAKE);

	otmp->nested = current_subject;
	current_subject->parent_subject = stmp;

	return;
}
