%{
#include "gradm.h"
extern int learn_pass1lex(void);

extern struct gr_learn_role_entry *default_role_entry;
extern struct gr_learn_role_entry **group_role_list;
extern struct gr_learn_role_entry **user_role_list;
extern struct gr_learn_role_entry **special_role_list;

%}

%union {
	char * string;
	unsigned long num;
}

%token <string> FILENAME ROLENAME
%token <num> NUM IPADDR;
%type <string> filename

%%

learn_logs:	learn_log
	|	learn_logs learn_log
	;

filename:	/*empty*/	{ $$ = strdup(""); }
	|	FILENAME	{
				  if (!strcmp($1, "//"))
					$1[1] = '\0';
				  $$ = $1;
				}
	;

learn_log:
		error
	|	ROLENAME ':' NUM ':' NUM ':' NUM ':' filename ':' filename ':' NUM ':' NUM ':' filename ':' NUM ':' IPADDR
		{
			struct gr_learn_role_entry *role;
			unsigned long res1, res2;
			__u16 rolemode;
			__u32 addr;

			rolemode = $3;
			res1 = $13;
			res2 = $15;

			addr = $21;

			if (rolemode & GR_ROLE_USER)
				role = insert_learn_role(&user_role_list, $1, rolemode);
			else if (rolemode & GR_ROLE_GROUP)
				role = insert_learn_role(&group_role_list, $1, rolemode);
			else if (rolemode & GR_ROLE_SPECIAL)
				role = insert_learn_role(&special_role_list, $1, rolemode);
			else {
				if (default_role_entry == NULL) {
					default_role_entry = calloc(1, sizeof(struct gr_learn_role_entry));
					if (!default_role_entry)
						failure("calloc");
				}

				role = default_role_entry;
			}

			if (rolemode & GR_ROLE_LEARN) {
				insert_ip(&(role->allowed_ips), addr, 0, 0, 0);
				if ((!strcmp($17, "") && strlen($9) > 1 && !res1 && !res2) || is_protected_path($17, $19))
					insert_learn_role_subject(role, conv_filename_to_struct($9, GR_FIND | GR_OVERRIDE));
			} else if (strlen($9) > 1)
				insert_learn_role_subject(role, conv_filename_to_struct($11, GR_FIND | GR_OVERRIDE));
		}		
	|	ROLENAME ':' NUM ':' NUM ':' NUM ':' filename ':' filename ':' IPADDR ':' NUM ':' NUM ':' NUM ':' NUM ':' IPADDR
		{
			struct gr_learn_role_entry *role;
			__u16 rolemode;
			__u32 addr;

			rolemode = $3;

			addr = $23;

			if (rolemode & GR_ROLE_USER)
				role = insert_learn_role(&user_role_list, $1, rolemode);
			else if (rolemode & GR_ROLE_GROUP)
				role = insert_learn_role(&group_role_list, $1, rolemode);
			else if (rolemode & GR_ROLE_SPECIAL)
				role = insert_learn_role(&special_role_list, $1, rolemode);
			else {
				if (default_role_entry == NULL) {
					default_role_entry = calloc(1, sizeof(struct gr_learn_role_entry));
					if (!default_role_entry)
						failure("calloc");
				}
	
				role = default_role_entry;
			}

			if (rolemode & GR_ROLE_LEARN) {
				insert_ip(&(role->allowed_ips), addr, 0, 0, 0);
				insert_learn_role_subject(role, conv_filename_to_struct($9, GR_FIND | GR_OVERRIDE));
			} else if (strlen($9) > 1)
				insert_learn_role_subject(role, conv_filename_to_struct($11, GR_FIND | GR_OVERRIDE));
		}
	;
%%
