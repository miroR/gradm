%{
#include "gradm.h"
extern int grlearn_configlex(void);
%}

%union {
	char * string;
	unsigned long num;
}

%token <string> FILENAME NOLEARN INHERITLEARN CACHESIZE
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
