%{
#include "gradm.h"
extern int learnlex(void);
%}

%union {
	char * string;
}

%token <string> NUM FILENAME IPADDR DATE JUNK
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
	|	DATE NUM ':' NUM ':' NUM ':' NUM ':' filename ':' NUM
		{
			__u16 s;
			__u32 l, l2, l3, l4;

			s = atoi($2);
			l = atol($4);
			l2 = atoi($6);
			l3 = atol($8);
			l4 = atol($12);
			add_learn_file_info(s, l, l2, l3, &($10), l4);
		}		
	|	DATE NUM ':' NUM ':' IPADDR ':' NUM ':' NUM ':' NUM ':' NUM
		{
			__u16 s, s2, s3, s4, s5;
			__u32 l, addr;
			struct in_addr ip;

			s = atoi($2);
			l = atol($4);

			if (inet_aton($6, &ip))
				addr = ip.s_addr;
			else
				addr = 0;

			s2 = atoi($8);
			s3 = atoi($10);
			s4 = atoi($12);
			s5 = atoi($14);

			add_learn_ip_info(s, l, addr, s2, s3, s4, s5);
		}
	;
%%
