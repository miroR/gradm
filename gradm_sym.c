#include "gradm.h"

struct object_variable {
	char *symname;
	struct var_object *object;
};

static struct object_variable *symtab = NULL;
static unsigned int symtab_size = 0;

void interpret_variable(char *variable)
{
	struct var_object *var;

	var = sym_retrieve(variable);

	for (; var; var = var->prev) {
		if (!add_proc_object_acl(current_subject, var->filename, var->mode, GR_FEXIST))
			exit(EXIT_FAILURE);
	}

	return;
}

void add_var_object(struct var_object **object, char *name, __u32 mode)
{
	struct var_object *v;

	v = (struct var_object *) calloc(1, sizeof(struct var_object));

	if (!v)
		failure("calloc");

	if (*object)
		(*object)->next = v;

	v->prev = *object;

	v->filename = name;
	v->mode = mode;

	*object = v;

	return;
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
