%{
#include "gradm.h"
#include "learn_pass2.tab.h"

void learn_pass2error(const char *s);
int learn_pass2wrap(void);
%}

ROLENAME [_a-zA-Z0-9-]{1,30}
NUM [0-9]+
FILENAME [/][^\t\n]*
IPADDR [0-9]{1,3}"."[0-9]{1,3}"."[0-9]{1,3}"."[0-9]{1,3}

%option nounput

%x ERROR

%%

{NUM}					{
					  learn_pass2lval.string = strdup(yytext);
					  return NUM;
					}
{ROLENAME}				{
					  learn_pass2lval.string = strdup(yytext);
					  return ROLENAME;
					}
{FILENAME}				{
					  learn_pass2lval.string = strdup(yytext);
					  return FILENAME;
					}
{IPADDR}				{
					  learn_pass2lval.string = strdup(yytext);
					  return IPADDR;
					}
[\t]					{ return ':'; }
.					;
%%

void learn_pass2error(const char *s) { return; }
int learn_pass2wrap(void) { return 1; }
