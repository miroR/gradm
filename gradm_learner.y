%{
#include "gradm.h"
extern int learnlex(void);
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
	|	ROLENAME ':' NUM ':' filename ':' NUM ':' NUM ':' filename ':' NUM
		{
			__u16 rolemode;
			__u32 l2, l3, l4;

			rolemode = atoi($3);
			l2 = atoi($7);
			l3 = atol($9);
			l4 = atol($13);
			add_learn_file_info($1, rolemode, $5, l2, l3, $11, l4);
		}		
	|	ROLENAME ':' NUM ':' filename ':' IPADDR ':' NUM ':' NUM ':' NUM ':' NUM
		{
			__u16 rolemode;
			__u16 s2, s3, s4, s5;
			__u32 addr;
			struct in_addr ip;

			rolemode = atoi($3);

			if (inet_aton($7, &ip))
				addr = ip.s_addr;
			else
				addr = 0;

			s2 = atoi($9);
			s3 = atoi($11);
			s4 = atoi($13);
			s5 = atoi($15);

			add_learn_ip_info($1, rolemode, $5, addr, s2, s3, s4, s5);
		}
	;
%%
