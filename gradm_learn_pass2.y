%{
#include "gradm.h"
extern int learn_pass2lex(void);

extern struct gr_learn_role_entry *default_role_entry;
extern struct gr_learn_role_entry **group_role_list;
extern struct gr_learn_role_entry **user_role_list;
extern struct gr_learn_role_entry **special_role_list;

%}

%union {
	char * string;
}

%token <string> NUM FILENAME IPADDR ROLENAME
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
			struct gr_learn_file_node *subjlist;
			struct gr_learn_file_node *subject;
			__u32 mode;
			__u16 rolemode;
			unsigned long res1, res2;

			rolemode = atoi($3);
			mode = atoi($19);
			res1 = atol($13);
			res2 = atol($15);


			if (rolemode & GR_ROLE_USER)
				role = insert_learn_role(&user_role_list, $1, rolemode);
			else if (rolemode & GR_ROLE_GROUP)
				role = insert_learn_role(&group_role_list, $1, rolemode);
			else if (rolemode & GR_ROLE_SPECIAL)
				role = insert_learn_role(&special_role_list, $1, rolemode);
			else
				role = default_role_entry;

			subjlist = role->subject_list;

			if (rolemode & GR_ROLE_LEARN)
				subject = match_file_node(subjlist, $9);
			else
				subject = match_file_node(subjlist, $11);
				
			if (strcmp($17, ""))
				insert_learn_object(subject, conv_filename_to_struct($17, mode | GR_FIND));
			else if ((strlen($9) > 1) && !res1 && !res2) {
				if (subject->subject == NULL) {
					subject->subject = calloc(1, sizeof(struct gr_learn_subject_node));
					if (subject->subject == NULL)
						failure("calloc");
				}
				subject->subject->cap_raise |= (1 << mode);
			}
		}		
	|	ROLENAME ':' NUM ':' NUM ':' NUM ':' filename ':' filename ':' IPADDR ':' NUM ':' NUM ':' NUM ':' NUM ':' IPADDR
		{
			struct gr_learn_role_entry *role;
			struct gr_learn_file_node *subjlist;
			struct gr_learn_file_node *subject;
			__u16 rolemode;
			struct in_addr ip;
			__u32 addr;
			__u16 port;
			__u8 mode, proto, socktype;

			mode = atoi($19);

			rolemode = atoi($3);
			if (inet_aton($13, &ip))
				addr = ip.s_addr;
			else
				addr = 0;

			port = atoi($15);
			socktype = atoi($17);
			proto = atoi($19);
			mode = atoi($21);

			if (rolemode & GR_ROLE_USER)
				role = insert_learn_role(&user_role_list, $1, rolemode);
			else if (rolemode & GR_ROLE_GROUP)
				role = insert_learn_role(&group_role_list, $1, rolemode);
			else if (rolemode & GR_ROLE_SPECIAL)
				role = insert_learn_role(&special_role_list, $1, rolemode);
			else
				role = default_role_entry;

			subjlist = role->subject_list;

			if (rolemode & GR_ROLE_LEARN)
				subject = match_file_node(subjlist, $9);
			else
				subject = match_file_node(subjlist, $11);
				
			if (mode == GR_IP_CONNECT)
				insert_ip(&(subject->connect_list), addr, port, proto, socktype);
			else if (mode == GR_IP_BIND)
				insert_ip(&(subject->bind_list), addr, port, proto, socktype);
		}
	;
%%
