%{
#include "gradm.h"
#include "fulllearn_pass3.tab.h"

void fulllearn_pass3error(const char *s);
int fulllearn_pass3wrap(void);
%}

ROLENAME [_a-zA-Z0-9-]{1,30}
NUM [0-9]+
FILENAME [/][^\t\n]*
IPADDR [0-9]{1,3}"."[0-9]{1,3}"."[0-9]{1,3}"."[0-9]{1,3}

%option nounput

%x ERROR

%%

{NUM}					{
					  fulllearn_pass3lval.string = strdup(yytext);
					  return NUM;
					}
{ROLENAME}				{
					  fulllearn_pass3lval.string = strdup(yytext);
					  return ROLENAME;
					}
{FILENAME}				{
					  fulllearn_pass3lval.string = strdup(yytext);
					  return FILENAME;
					}
{IPADDR}				{
					  fulllearn_pass3lval.string = strdup(yytext);
					  return IPADDR;
					}
[\t]					{ return ':'; }
.					;
%%

void fulllearn_pass3error(const char *s) { return; }
int fulllearn_pass3wrap(void) { return 1; }
