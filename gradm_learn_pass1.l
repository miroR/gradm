%{
#include "gradm.h"
#include "learn_pass1.tab.h"

void learn_pass1error(const char *s);
int learn_pass1wrap(void);
static struct in_addr ip;
%}

ROLENAME [_a-zA-Z0-9-]{1,30}
NUM [0-9]+
FILENAME [/][^\t\n]*
IPADDR [0-9]{1,3}"."[0-9]{1,3}"."[0-9]{1,3}"."[0-9]{1,3}

%option nounput

%x ERROR

%%

{NUM}					{
					  learn_pass1lval.num = atol(yytext);
					  return NUM;
					}
{ROLENAME}				{
					  learn_pass1lval.string = strdup(yytext);
					  return ROLENAME;
					}
{FILENAME}				{
					  unsigned int len = strlen(yytext);
					  char *p = yytext;
					  if (len > 10 && !strcmp(p + len - 10, " (deleted)"))
						*(p + len - 10) = '\0';
					  learn_pass1lval.string = strdup(yytext);
					  return FILENAME;
					}
{IPADDR}				{
					  if (inet_aton(yytext, &ip))
						learn_pass1lval.num = ip.s_addr;
					  else
						learn_pass1lval.num = 0;
					  return IPADDR;
					}
[\t]					{ return ':'; }
.					;
%%

void learn_pass1error(const char *s) { return; }
int learn_pass1wrap(void) { return 1; }
