%{
#include "gradm.h"
extern int grlearnlex(void);
%}

%union {
	char * string;
	unsigned long num;
}

%token <string> FILENAME
%token <num> NUM

%%

learn_config_file:	learn_config
		|	learn_config_file learn_config
		;

learn_config:
		NOLEARN FILENAME
	|	INHERITLEARN FILENAME
	|	CACHESIZE NUM
	;
%%
