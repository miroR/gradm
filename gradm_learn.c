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

struct gr_learn_role_entry *default_role_entry;
struct gr_learn_role_entry *group_role_list;
struct gr_learn_role_entry *user_role_list;
struct gr_learn_role_entry *special_role_list;

extern FILE *learn_pass1in;
extern FILE *learn_pass2in;
extern int learn_pass1parse(void);
extern int learn_pass2parse(void);

void learn_pass1(FILE *stream)
{
	struct gr_learn_role_entry *tmp;
	struct gr_learn_file_tmp_node **tmptable;
	unsigned long i;
	u_int32_t table_size;

	learn_pass1in = stream;
	learn_pass1parse();

	if (default_role_entry && default_role_entry->hash) {
		if (default_role_entry->hash) {
			tmptable = (struct gr_learn_file_tmp_node **)default_role_entry->hash->table;
			table_size = default_role_entry->hash->table_size;
			sort_file_list(default_role_entry->hash);
			for (i = 0; i < table_size; i++) {
				if (tmptable[i] == NULL)
					continue;
				if (default_role_entry->rolemode & GR_ROLE_LEARN)
					insert_file(&(default_role_entry->subject_list), tmptable[i]->filename, tmptable[i]->mode, 1);
				else
					insert_file(&(default_role_entry->subject_list), tmptable[i]->filename, tmptable[i]->mode, 2);
			}
		}
		if (default_role_entry->rolemode & GR_ROLE_LEARN)
			reduce_ip_tree(default_role_entry->allowed_ips);
	}

	for_each_list_entry(tmp, group_role_list) {
		if (tmp->hash) {
			tmptable = (struct gr_learn_file_tmp_node **)tmp->hash->table;
			table_size = tmp->hash->table_size;
			sort_file_list(tmp->hash);
			for (i = 0; i < table_size; i++) {
				if (tmptable[i] == NULL)
					continue;
				if (tmp->rolemode & GR_ROLE_LEARN)
					insert_file(&(tmp->subject_list), tmptable[i]->filename, tmptable[i]->mode, 1);
				else
					insert_file(&(tmp->subject_list), tmptable[i]->filename, tmptable[i]->mode, 2);
			}
		}
		if (tmp->rolemode & GR_ROLE_LEARN)
			reduce_ip_tree(tmp->allowed_ips);
	}

	for_each_list_entry(tmp, user_role_list) {
		if (tmp->hash) {
			tmptable = (struct gr_learn_file_tmp_node **)tmp->hash->table;
			table_size = tmp->hash->table_size;
			sort_file_list(tmp->hash);
			for (i = 0; i < table_size; i++) {
				if (tmptable[i] == NULL)
					continue;
				if (tmp->rolemode & GR_ROLE_LEARN)
					insert_file(&(tmp->subject_list), tmptable[i]->filename, tmptable[i]->mode, 1);
				else
					insert_file(&(tmp->subject_list), tmptable[i]->filename, tmptable[i]->mode, 2);
			}
		}
		if (tmp->rolemode & GR_ROLE_LEARN)
			reduce_ip_tree(tmp->allowed_ips);
	}

	for_each_list_entry(tmp, special_role_list) {
		if (tmp->hash) {
			tmptable = (struct gr_learn_file_tmp_node **)tmp->hash->table;
			table_size = tmp->hash->table_size;
			sort_file_list(tmp->hash);
			for (i = 0; i < table_size; i++) {
				if (tmptable[i] == NULL)
					continue;
				if (tmp->rolemode & GR_ROLE_LEARN)
					insert_file(&(tmp->subject_list), tmptable[i]->filename, tmptable[i]->mode, 1);
				else
					insert_file(&(tmp->subject_list), tmptable[i]->filename, tmptable[i]->mode, 2);
			}
		}
		if (tmp->rolemode & GR_ROLE_LEARN)
			reduce_ip_tree(tmp->allowed_ips);
	}

	return;
}

void merge_acl_rules(void)
{
	struct gr_learn_role_entry *matchrole = NULL;
	struct gr_learn_file_node *matchsubj = NULL;
	struct role_acl *role;
	struct proc_acl *subject;
	struct file_acl *object;
	struct ip_acl *ipp;
	unsigned int i, x, y, port;

	for_each_role(role, current_role) {
		if (role->roletype & GR_ROLE_LEARN)
			continue;

		if (role->roletype & GR_ROLE_USER)
			matchrole = find_learn_role(user_role_list, role->rolename);
		else if (role->roletype & GR_ROLE_GROUP)
			matchrole = find_learn_role(group_role_list, role->rolename);
		else if (role->roletype & GR_ROLE_SPECIAL)
			matchrole = find_learn_role(special_role_list, role->rolename);
		else
			matchrole = default_role_entry;

		for_each_subject(subject, role) {
			if (matchrole)
				matchsubj = match_file_node(matchrole->subject_list, subject->filename);
			if (matchrole && matchsubj) {
				if (!(subject->mode & (GR_LEARN | GR_INHERITLEARN))) {
					matchsubj->dont_display = 1;
					continue;
				}
				if (matchsubj->subject == NULL) {
					matchsubj->subject = (struct gr_learn_subject_node *)calloc(1, sizeof(struct gr_learn_subject_node));
					if (matchsubj->subject == NULL)
						failure("calloc");
				}

				matchsubj->mode |= subject->mode;
				/* learned subject was using policy inheritance */
				if (subject->parent_subject)
					matchsubj->mode &= ~GR_OVERRIDE;

				matchsubj->subject->pax_flags = subject->pax_flags;

				matchsubj->subject->cap_raise = cap_combine(matchsubj->subject->cap_raise,
									    cap_intersect(cap_invert(subject->cap_drop), subject->cap_mask));
				matchsubj->subject->resmask |= subject->resmask;

				matchsubj->subject->inaddr_any_override = subject->inaddr_any_override;

				for (i = 0; i < SIZE(subject->sock_families); i++)
					matchsubj->subject->sock_families[i] |= subject->sock_families[i];

				for (i = 0; i < subject->user_trans_num; i++) {
					x = *(subject->user_transitions + i);
					insert_learn_id_transition(&(matchsubj->user_trans_list), x, x, x);
				}
				for (i = 0; i < subject->group_trans_num; i++) {
					x = *(subject->group_transitions + i);
					insert_learn_id_transition(&(matchsubj->group_trans_list), x, x, x);
				}
				for (i = 0; i < GR_NLIMITS; i++) {
					if (subject->res[i].rlim_cur > matchsubj->subject->res[i].rlim_cur)
						matchsubj->subject->res[i].rlim_cur = subject->res[i].rlim_cur;
					if (subject->res[i].rlim_max > matchsubj->subject->res[i].rlim_max)
						matchsubj->subject->res[i].rlim_max = subject->res[i].rlim_max;
				}
				for_each_file_object(object, subject) {
					insert_learn_object(matchsubj, conv_filename_to_struct(object->filename, object->mode));
				}
				for (i = 0; i < subject->ip_num; i++) {
					ipp = subject->ips[i];
					if (ipp->mode == GR_IP_CONNECT) {
						for (port = ipp->low; port <= ipp->high; port++)
						for (x = 0; x < 5; x++)
						for (y = 0; y < 256; y++)
						if ((ipp->type & (1U << x)) && (ipp->proto[y / 32] & (1U << y % 32)))
							insert_ip(&(matchsubj->connect_list), ipp->addr, port, x, y);
					} else if (ipp->mode == GR_IP_BIND) {
						for (port = ipp->low; port <= ipp->high; port++)
						for (x = 0; x < 5; x++)
						for (y = 0; y < 256; y++)
						if ((ipp->type & (1U << x)) && (ipp->proto[y / 32] & (1U << y % 32)))
							insert_ip(&(matchsubj->bind_list), ipp->addr, port, x, y);
					}
				}
			}
		}
	}
			

	return;
}

void learn_pass2(FILE *stream)
{
	struct gr_learn_role_entry *tmp;
	struct gr_learn_file_node *subjects;
	
	learn_pass2in = stream;
	learn_pass2parse();

	merge_acl_rules();

	if (default_role_entry) {
		subjects = default_role_entry->subject_list;
		traverse_file_tree(subjects, &full_reduce_object_node, NULL, NULL);
		traverse_file_tree(subjects, &full_reduce_ip_node, NULL, NULL);
		traverse_file_tree(subjects, &ensure_subject_security, NULL, NULL);
	}

	for_each_list_entry(tmp, group_role_list) {
		subjects = tmp->subject_list;
		traverse_file_tree(subjects, &full_reduce_object_node, NULL, NULL);
		traverse_file_tree(subjects, &full_reduce_ip_node, NULL, NULL);
		traverse_file_tree(subjects, &ensure_subject_security, NULL, NULL);
	}

	for_each_list_entry(tmp, user_role_list) {
		subjects = tmp->subject_list;
		traverse_file_tree(subjects, &full_reduce_object_node, NULL, NULL);
		traverse_file_tree(subjects, &full_reduce_ip_node, NULL, NULL);
		traverse_file_tree(subjects, &ensure_subject_security, NULL, NULL);
	}

	for_each_list_entry(tmp, special_role_list) {
		subjects = tmp->subject_list;
		traverse_file_tree(subjects, &full_reduce_object_node, NULL, NULL);
		traverse_file_tree(subjects, &full_reduce_ip_node, NULL, NULL);
		traverse_file_tree(subjects, &ensure_subject_security, NULL, NULL);
	}

	return;
}

void
perform_parse_and_reduce(FILE *learnlog)
{
	learn_pass1(learnlog);
	fseek(learnlog, 0, SEEK_SET);
	learn_pass2(learnlog);

	fclose(learnlog);

	return;
}

void display_learn_logs(FILE *stream)
{
	struct gr_learn_role_entry *tmp;
	struct gr_learn_file_node *subjects;
	struct gr_learn_ip_node *allowed_ips;
	char rolemode[17];
	
	if (default_role_entry) {
		if (!(default_role_entry->rolemode & GR_ROLE_LEARN))
			fprintf(stream, "###  THE BELOW SUBJECT(S) SHOULD BE ADDED TO THE DEFAULT ROLE ###\n");
		else
			fprintf(stream, "role default G\n");
		subjects = default_role_entry->subject_list;
		allowed_ips = default_role_entry->allowed_ips;
		if (allowed_ips && !(grlearn_options & GR_DONT_LEARN_ALLOWED_IPS))
			traverse_ip_tree(allowed_ips, NULL, &display_only_ip, 0, stream);
		if (subjects) {
			sort_file_node_list(default_role_entry->subject_list);
			display_tree_with_role(subjects, "default", stream);
		}

		fprintf(stream, "\n");
	}

	for_each_list_entry(tmp, group_role_list) {
		if (!(tmp->rolemode & GR_ROLE_LEARN))
			fprintf(stream, "###  THE BELOW SUBJECT(S) SHOULD BE ADDED TO THE GROUP ROLE \"%s\" ###\n", tmp->rolename);
		else {
			conv_role_mode_to_str(tmp->rolemode, rolemode, sizeof(rolemode));
			fprintf(stream, "role %s %s\n", tmp->rolename, rolemode);
		}
		subjects = tmp->subject_list;
		allowed_ips = tmp->allowed_ips;
		if (allowed_ips && !(grlearn_options & GR_DONT_LEARN_ALLOWED_IPS))
			traverse_ip_tree(allowed_ips, NULL, &display_only_ip, 0, stream);
		if (subjects) {
			sort_file_node_list(group_role_list->subject_list);
			display_tree_with_role(subjects, tmp->rolename, stream);
		}

		fprintf(stream, "\n");
	}

	for_each_list_entry(tmp, user_role_list) {
		if (!(tmp->rolemode & GR_ROLE_LEARN))
			fprintf(stream, "###  THE BELOW SUBJECT(S) SHOULD BE ADDED TO THE USER ROLE \"%s\" ###\n", tmp->rolename);
		else {
			conv_role_mode_to_str(tmp->rolemode, rolemode, sizeof(rolemode));
			fprintf(stream, "role %s %s\n", tmp->rolename, rolemode);
		}
		subjects = tmp->subject_list;
		allowed_ips = tmp->allowed_ips;
		if (allowed_ips && !(grlearn_options & GR_DONT_LEARN_ALLOWED_IPS))
			traverse_ip_tree(allowed_ips, NULL, &display_only_ip, 0, stream);
		if (subjects) {
			sort_file_node_list(user_role_list->subject_list);
			display_tree_with_role(subjects, tmp->rolename, stream);
		}

		fprintf(stream, "\n");
	}

	for_each_list_entry(tmp, special_role_list) {
		if (!(tmp->rolemode & GR_ROLE_LEARN))
			fprintf(stream, "###  THE BELOW SUBJECT(S) SHOULD BE ADDED TO THE SPECIAL ROLE \"%s\" ###\n", tmp->rolename);
		else {
			conv_role_mode_to_str(tmp->rolemode, rolemode, sizeof(rolemode));
			fprintf(stream, "role %s %s\n", tmp->rolename, rolemode);
		}
		subjects = tmp->subject_list;
		allowed_ips = tmp->allowed_ips;
		if (allowed_ips && !(grlearn_options & GR_DONT_LEARN_ALLOWED_IPS))
			traverse_ip_tree(allowed_ips, NULL, &display_only_ip, 0, stream);
		if (subjects) {
			sort_file_node_list(special_role_list->subject_list);
			display_tree_with_role(subjects, tmp->rolename, stream);
		}

		fprintf(stream, "\n");
	}

	return;
}


void
handle_learn_logs(FILE *learnlog, FILE * stream)
{
	struct glob_file *glob;

	parse_acls();
	expand_acls();

	/* since we don't call analyze_acls(), we'll defer the errors till they load the policy */
	for (glob = glob_files_head; glob; glob = glob->next)
		add_globbed_object_acl(glob->subj, glob->filename, glob->mode, glob->type, glob->policy_file, glob->lineno);

	perform_parse_and_reduce(learnlog);
	display_learn_logs(stream);

	return;
}
