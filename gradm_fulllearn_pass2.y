%{
#include "gradm.h"
extern int fulllearn_pass2lex(void);

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
			uid_t uid;
			gid_t gid;
			unsigned long res1, res2;
			struct in_addr ip;
			__u32 addr;

			uid = atoi($5);
			gid = atoi($7);
			res1 = atol($13);
			res2 = atol($15);

			if (inet_aton($21, &ip))
				addr = ip.s_addr;
			else
				addr = 0;				

			match_role(role_list, uid, gid, &group, &user);
			if (user)
				insert_ip(&(user->allowed_ips), addr, 0, 0, 0);
			else if (group)
				insert_ip(&(group->allowed_ips), addr, 0, 0, 0);
				
			if (user && ((!strcmp($17, "")  && strlen($9) > 1 && !res1 && !res2) || is_protected_path($17, atoi($19))))
				insert_temp_file(&(user->tmp_subject_list), $9, GR_FIND | GR_OVERRIDE);
			else if (group && ((!strcmp($17, "") && strlen($9) > 1 && !res1 && !res2) || is_protected_path($17, atoi($19))))
				insert_temp_file(&(group->tmp_subject_list), $9, GR_FIND | GR_OVERRIDE);
		}		
	|	ROLENAME ':' NUM ':' NUM ':' NUM ':' filename ':' filename ':' IPADDR ':' NUM ':' NUM ':' NUM ':' NUM ':' IPADDR
		{
			struct gr_learn_group_node *group = NULL;
			struct gr_learn_user_node *user = NULL;
			uid_t uid;
			gid_t gid;
			struct in_addr ip;
			__u32 addr;

			uid = atoi($5);
			gid = atoi($7);

			if (inet_aton($23, &ip))
				addr = ip.s_addr;
			else
				addr = 0;				

			match_role(role_list, uid, gid, &group, &user);
			if (user)
				insert_ip(&(user->allowed_ips), addr, 0, 0, 0);
			else if (group)
				insert_ip(&(group->allowed_ips), addr, 0, 0, 0);

			if (user)
				insert_temp_file(&(user->tmp_subject_list), $9, GR_FIND | GR_OVERRIDE);
			else if (group)
				insert_temp_file(&(group->tmp_subject_list), $9, GR_FIND | GR_OVERRIDE);
		}
	;
%%
