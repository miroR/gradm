%{
#include "gradm.h"
#include "grlearn.tab.h"

void grlearnerror(const char *s);
int grlearnwrap(void);
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
					  learn_pass1lval.num = atol(yytext);
					  return NUM;
					}
{FILENAME}				{
					  learn_pass1lval.string = strdup(yytext);
					  return FILENAME;
					}
.					;
%%

void grlearnerror(const char *s) { return; }
int grlearnwrap(void) { return 1; }
