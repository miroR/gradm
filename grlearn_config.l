%{
#include "gradm.h"
#include "grlearn_config.tab.h"

void grlearn_configerror(const char *s);
int grlearn_configwrap(void);
%}

NUM [0-9]+
FILENAME [/][^\t\n]*

%option nounput

%x ERROR

%%

"inherit-learn"				{
					  return INHERITLEARN;
					}
"no-learn"				{
					  return NOLEARN;
					}
"cache-size"				{
					  return CACHESIZE;
					}

{NUM}					{
					  grlearn_configlval.num = atol(yytext);
					  return NUM;
					}
{FILENAME}				{
					  grlearn_configlval.string = strdup(yytext);
					  return FILENAME;
					}
.					;
%%

void grlearn_configerror(const char *s) { return; }
int grlearn_configwrap(void) { return 1; }
