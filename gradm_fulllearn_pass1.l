%{
#include "gradm.h"
#include "fulllearn_pass1.tab.h"

void fulllearn_pass1error(const char *s);
int fulllearn_pass1wrap(void);
%}

ROLENAME [_a-zA-Z0-9-]{1,30}
NUM [0-9]+
FILENAME [/][A-Za-z0-9@\-_#., /]*
IPADDR [0-9]{1,3}"."[0-9]{1,3}"."[0-9]{1,3}"."[0-9]{1,3}

%option nounput

%x ERROR

%%

{NUM}					{
					  fulllearn_pass1lval.string = strdup(yytext);
					  return NUM;
					}
{ROLENAME}				{
					  fulllearn_pass1lval.string = strdup(yytext);
					  return ROLENAME;
					}
{FILENAME}				{
					  fulllearn_pass1lval.string = strdup(yytext);
					  return FILENAME;
					}
{IPADDR}				{
					  fulllearn_pass1lval.string = strdup(yytext);
					  return IPADDR;
					}
:					{ return ':'; }
.					;
%%

void fulllearn_pass1error(const char *s) { return; }
int fulllearn_pass1wrap(void) { return 1; }
