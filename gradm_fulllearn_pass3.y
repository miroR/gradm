%{
#include "gradm.h"
extern int fulllearn_pass3lex(void);

extern struct gr_learn_group_node **role_list;
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
			struct gr_learn_group_node *group = NULL;
			struct gr_learn_user_node *user = NULL;
			struct gr_learn_file_node *subjlist = NULL;
			struct gr_learn_file_node *subject = NULL;
			uid_t uid;
			gid_t gid;
			__u32 mode;
			unsigned long res1, res2;

			uid = atoi($5);
			gid = atoi($7);
			mode = atoi($19);
			res1 = atol($13);
			res2 = atol($15);

			match_role(role_list, uid, gid, &group, &user);
			if (user)
				subjlist = user->subject_list;
			else if (group)
				subjlist = group->subject_list;

			if (subjlist)
				subject = match_file_node(subjlist, $9);
			if (subject && strcmp($17, ""))
				insert_temp_file(&(subject->tmp_object_list), $17, mode | GR_FIND);
			else if (subject && strlen($9) > 1 && !res1 && !res2) {
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
			struct gr_learn_group_node *group = NULL;
			struct gr_learn_user_node *user = NULL;
			struct gr_learn_file_node *subjlist = NULL;
			struct gr_learn_file_node *subject = NULL;
			uid_t uid;
			gid_t gid;
			struct in_addr ip;
			__u32 addr;
			__u16 port;
			__u8 mode, proto, socktype;

			uid = atoi($5);
			gid = atoi($7);
			mode = atoi($19);

			if (inet_aton($13, &ip))
				addr = ip.s_addr;
			else
				addr = 0;

			port = atoi($15);
			socktype = atoi($17);
			proto = atoi($19);
			mode = atoi($21);

			match_role(role_list, uid, gid, &group, &user);
			if (user)
				subjlist = user->subject_list;
			else if (group)
				subjlist = group->subject_list;

			if (subjlist)
				subject = match_file_node(subjlist, $9);
			if (subject && mode == GR_IP_CONNECT)
				insert_ip(&(subject->connect_list), addr, port, proto, socktype);
			else if (subject && mode == GR_IP_BIND)
				insert_ip(&(subject->bind_list), addr, port, proto, socktype);
		}
	;
%%
