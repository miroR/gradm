%{
#include "gradm.h"
extern int learnlex(void);
%}

%union {
	char * string;
}

%token <string> NUM FILENAME IPADDR DATE JUNK ROLENAME
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
	|	DATE ROLENAME ':' NUM ':' filename ':' NUM ':' NUM ':' filename ':' NUM
		{
			__u16 rolemode;
			__u32 l2, l3, l4;

			rolemode = atoi($4);
			l2 = atoi($8);
			l3 = atol($10);
			l4 = atol($14);
			add_learn_file_info($2, rolemode, $6, l2, l3, $12, l4);
		}		
	|	DATE ROLENAME ':' NUM ':' filename ':' IPADDR ':' NUM ':' NUM ':' NUM ':' NUM
		{
			__u16 rolemode;
			__u16 s2, s3, s4, s5;
			__u32 addr;
			struct in_addr ip;

			rolemode = atoi($4);

			if (inet_aton($8, &ip))
				addr = ip.s_addr;
			else
				addr = 0;

			s2 = atoi($10);
			s3 = atoi($12);
			s4 = atoi($14);
			s5 = atoi($16);

			add_learn_ip_info($2, rolemode, $6, addr, s2, s3, s4, s5);
		}
	;
%%
