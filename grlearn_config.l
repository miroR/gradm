%{
#include "gradm.h"
#include "grlearn_config.tab.h"

void grlearn_configerror(const char *s);
int grlearn_configwrap(void);
%}

NUM [0-9]+
FILENAME [/][^\t\n]*

%option nounput

%x ERROR COMMENT_STATE

%%

"#"					{
					  BEGIN(COMMENT_STATE);
					}
"\n"					{
					  BEGIN(INITIAL);
					}
"inherit-learn"				{
					  return INHERITLEARN;
					}
"inherit-no-learn"			{
					  return INHERITNOLEARN;
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
