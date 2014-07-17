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

struct object_variable {
	char *symname;
	struct var_object *object;
};

static struct object_variable *symtab = NULL;
static unsigned int symtab_size = 0;

void interpret_variable(struct var_object *var)
{
	struct var_object *tmp;
	struct var_object *varhead = get_list_head(var);

	for_each_variable(tmp, varhead) {
		switch (tmp->type) {
		case VAR_FILE_OBJECT:
			add_proc_object_acl(current_subject, tmp->file_obj.filename, tmp->file_obj.mode, GR_FEXIST);
			break;
		case VAR_NET_OBJECT:
			if (tmp->net_obj.host)
				add_host_acl(current_subject, tmp->net_obj.mode, tmp->net_obj.host, &tmp->net_obj.ip);
			else
				add_ip_acl(current_subject, tmp->net_obj.mode, &tmp->net_obj.ip);
			break;
		case VAR_CAP_OBJECT:
			add_cap_acl(current_subject, tmp->cap_obj.cap, tmp->cap_obj.audit);
			break;
		default:
			break;
		}
	}

	return;
}

struct var_object * intersect_objects(struct var_object *var1, struct var_object *var2)
{
	struct var_object *tmpvar1, *tmpvar2, *retvar = NULL;
	struct var_object *var1head = get_list_head(var1);
	struct var_object *var2head = get_list_head(var2);

	for_each_variable(tmpvar1, var1head) {
		switch (tmpvar1->type) {
		case VAR_FILE_OBJECT:
			for_each_variable(tmpvar2, var2head) {
				switch (tmpvar2->type) {
				case VAR_FILE_OBJECT:
					if (!strcmp(tmpvar1->file_obj.filename, tmpvar2->file_obj.filename)) {
						add_file_var_object(&retvar, tmpvar1->file_obj.filename, tmpvar1->file_obj.mode & tmpvar2->file_obj.mode);
						break;
					}
					break;
				default:
					break;
				}
			}
			break;
		default:
			break;
		}
	}

	return retvar;
}

struct var_object * union_objects(struct var_object *var1, struct var_object *var2)
{
	struct var_object *tmpvar1, *tmpvar2, *retvar = NULL;
	struct var_object *var1head = get_list_head(var1);
	struct var_object *var2head = get_list_head(var2);
	int found_dupe = 0;

	for_each_variable(tmpvar1, var1head) {
		switch (tmpvar1->type) {
		case VAR_FILE_OBJECT:
			found_dupe = 0;
			for_each_variable(tmpvar2, var2head) {
				switch (tmpvar2->type) {
				case VAR_FILE_OBJECT:
					if (!strcmp(tmpvar1->file_obj.filename, tmpvar2->file_obj.filename)) {
						add_file_var_object(&retvar, tmpvar1->file_obj.filename, tmpvar1->file_obj.mode | tmpvar2->file_obj.mode);
						found_dupe = 1;
						break;
					}
					break;
				default:
					break;
				}
			}
			if (!found_dupe)
				add_file_var_object(&retvar, tmpvar1->file_obj.filename, tmpvar1->file_obj.mode);
			break;
		default:
			break;
		}
	}

	for_each_variable(tmpvar2, var2head) {
		switch (tmpvar2->type) {
		case VAR_FILE_OBJECT:
			found_dupe = 0;
			for_each_variable(tmpvar1, var1head) {
				switch (tmpvar1->type) {
				case VAR_FILE_OBJECT:
					if (!strcmp(tmpvar1->file_obj.filename, tmpvar2->file_obj.filename)) {
						found_dupe = 1;
						break;
					}
					break;
				default:
					break;
				}
			}

			if (!found_dupe)
				add_file_var_object(&retvar, tmpvar2->file_obj.filename, tmpvar2->file_obj.mode);
			break;
		default:
			break;
		}
	}

	return retvar;
}

struct var_object * differentiate_objects(struct var_object *var1, struct var_object *var2)
{
	struct var_object *tmpvar1, *tmpvar2, *retvar = NULL;
	struct var_object *var1head = get_list_head(var1);
	struct var_object *var2head = get_list_head(var2);
	int found_dupe = 0;
	char *path;

	for_each_variable(tmpvar1, var1head) {
		switch (tmpvar1->type) {
		case VAR_FILE_OBJECT:
			path = gr_strdup(tmpvar1->file_obj.filename);
			found_dupe = 0;
			do {
				for_each_variable(tmpvar2, var2head) {
					switch (tmpvar2->type) {
					case VAR_FILE_OBJECT:
						if (!strcmp(path, tmpvar2->file_obj.filename)) {
							found_dupe = 1;
							add_file_var_object(&retvar, tmpvar1->file_obj.filename, tmpvar1->file_obj.mode & ~tmpvar2->file_obj.mode);
							goto done;
						}
						break;
					default:
						break;
					}
				}
			} while(parent_dir(tmpvar1->file_obj.filename, &path));
done:
			if (!found_dupe)
				add_file_var_object(&retvar, tmpvar1->file_obj.filename, tmpvar1->file_obj.mode);
			free(path);
			break;
		default:
			break;
		}
	}

	return retvar;
}

void add_var_object(struct var_object **object, struct var_object *var)
{
	struct var_object *v;

	v = (struct var_object *) calloc(1, sizeof(struct var_object));

	if (!v)
		failure("calloc");

	if (*object)
		(*object)->next = v;

	memcpy(v, var, sizeof(struct var_object));

	v->prev = *object;
	v->next = NULL;

	*object = v;

	return;
}

void add_file_var_object(struct var_object **object, const char *name, u_int32_t mode)
{
	struct var_object var;

	var.type = VAR_FILE_OBJECT;
	var.file_obj.filename = name;
	var.file_obj.mode = mode;

	add_var_object(object, &var);
}

void add_net_var_object(struct var_object **object, struct ip_acl *ip, u_int8_t mode, const char *host)
{
	struct var_object var;

	var.type = VAR_NET_OBJECT;
	memcpy(&var.net_obj.ip, ip, sizeof(struct ip_acl));
	var.net_obj.mode = mode;
	var.net_obj.host = host ? gr_strdup(host) : NULL;

	add_var_object(object, &var);
}

void add_cap_var_object(struct var_object **object, const char *name, const char *audit)
{
	struct var_object var;

	var.type = VAR_CAP_OBJECT;
	var.cap_obj.cap = name ? gr_strdup(name) : NULL;
	var.cap_obj.audit = audit ? gr_strdup(audit) : NULL;

	add_var_object(object, &var);
}

struct var_object * sym_retrieve(char *symname)
{
	unsigned int i;

	for (i = 0; i < symtab_size; i++)
		if (!strcmp(symname, symtab[i].symname))
			return symtab[i].object;

	return NULL;
}

void sym_store(char *symname, struct var_object *object)
{
	symtab_size++;

	symtab = (struct object_variable *)gr_realloc(symtab, symtab_size * sizeof(struct object_variable));
	symtab[symtab_size - 1].symname = symname;
	symtab[symtab_size - 1].object = object;

	return;
}
