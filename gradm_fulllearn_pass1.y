%{
#include "gradm.h"
extern int fulllearn_pass1lex(void);

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
			struct passwd *pwd;
			struct group *grp;
			uid_t uid;
			gid_t gid;

			uid = atoi($5);
			gid = atoi($7);

			pwd = getpwuid(uid);
			grp = getgrgid(gid);

			if (pwd && grp)
				insert_user(&role_list, strdup(pwd->pw_name), strdup(grp->gr_name), uid, gid);
		}		
	|	ROLENAME ':' NUM ':' NUM ':' NUM ':' filename ':' filename ':' IPADDR ':' NUM ':' NUM ':' NUM ':' NUM ':' IPADDR
		{
			struct passwd *pwd;
			struct group *grp;
			uid_t uid;
			gid_t gid;

			uid = atoi($5);
			gid = atoi($7);

			pwd = getpwuid(uid);
			grp = getgrgid(gid);

			if (pwd && grp)
				insert_user(&role_list, strdup(pwd->pw_name), strdup(grp->gr_name), uid, gid);
		}
	;
%%
