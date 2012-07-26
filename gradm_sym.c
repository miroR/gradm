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
	for (tmp = var; tmp->prev; tmp = tmp->prev)
		;

	for (; tmp; tmp = tmp->next) {
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

	for (tmpvar1 = var1; tmpvar1; tmpvar1 = tmpvar1->prev) {
		switch (tmpvar1->type) {
		case VAR_FILE_OBJECT:
			for (tmpvar2 = var2; tmpvar2; tmpvar2 = tmpvar2->prev) {
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
	int found_dupe = 0;

	for (tmpvar1 = var1; tmpvar1; tmpvar1 = tmpvar1->prev) {
		switch (tmpvar1->type) {
		case VAR_FILE_OBJECT:
			found_dupe = 0;
			for (tmpvar2 = var2; tmpvar2; tmpvar2 = tmpvar2->prev) {
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

	for (tmpvar2 = var2; tmpvar2; tmpvar2 = tmpvar2->prev) {
		switch (tmpvar2->type) {
		case VAR_FILE_OBJECT:
			found_dupe = 0;
			for (tmpvar1 = var1; tmpvar1; tmpvar1 = tmpvar1->prev) {
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
	int found_dupe = 0;
	char *path;

	for (tmpvar1 = var1; tmpvar1; tmpvar1 = tmpvar1->prev) {
		switch (tmpvar1->type) {
		case VAR_FILE_OBJECT:
			path = calloc(strlen(tmpvar1->file_obj.filename) + 1, sizeof(char));
			if (!path)
				failure("calloc");
			strcpy(path, tmpvar1->file_obj.filename);
			found_dupe = 0;
			do {
				for (tmpvar2 = var2; tmpvar2; tmpvar2 = tmpvar2->prev) {
					switch (tmpvar2->type) {
					case VAR_FILE_OBJECT:
						if (!strcmp(path, tmpvar2->file_obj.filename)) {
							found_dupe = 1;
							add_file_var_object(&retvar, tmpvar1->file_obj.filename, tmpvar1->file_obj.mode &= ~tmpvar2->file_obj.mode);
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

void add_file_var_object(struct var_object **object, char *name, u_int32_t mode)
{
	struct var_object var;

	var.type = VAR_FILE_OBJECT;
	var.file_obj.filename = name;
	var.file_obj.mode = mode;

	add_var_object(object, &var);
}

void add_net_var_object(struct var_object **object, struct ip_acl *ip, u_int8_t mode, char *host)
{
	struct var_object var;

	var.type = VAR_NET_OBJECT;
	memcpy(&var.net_obj.ip, ip, sizeof(struct ip_acl));
	var.net_obj.mode = mode;
	var.net_obj.host = host ? gr_strdup(host) : NULL;

	add_var_object(object, &var);	
}

void add_cap_var_object(struct var_object **object, char *name, char *audit)
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

	symtab = realloc(symtab, symtab_size * sizeof(struct object_variable));

	if (symtab == NULL)
		failure("realloc");

	symtab[symtab_size - 1].symname = symname;
	symtab[symtab_size - 1].object = object;

	return;
}
