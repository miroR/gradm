%{
#include "gradm.h"
#include "learn.tab.h"

extern int learnparse(void);
void learnerror(const char *s);
int learnwrap(void);
%}

DATE [A-Z][a-z][a-z][ ]{1,2}[0-9]{1,2}" "[0-9][0-9]:[0-9][0-9]:[0-9][0-9]
HOSTKERNGRSEC [A-Za-z0-9\-]+" kernel: grsec: LEARN:"
METALOGKERNGRSEC [A-Za-z0-9\-]+" [kernel] grsec: LEARN:"
SYSLOGNGKERNGRSEC [A-Za-z0-9@\-]+" grsec: LEARN:"
ROLENAME [_a-zA-Z0-9-]{1,30}
NUM [0-9]+
FILENAME [/][A-Za-z0-9@\-_#., /]*
IPADDR [0-9]{1,3}"."[0-9]{1,3}"."[0-9]{1,3}"."[0-9]{1,3}

%option nounput

%x ERROR

%%

^{DATE}" "{HOSTKERNGRSEC} 		{ return DATE; }
^{DATE}" "{METALOGKERNGRSEC} 		{ return DATE; }
^{DATE}" "{SYSLOGNGKERNGRSEC} 		{ return DATE; }
{NUM}					{
					  learnlval.string = strdup(yytext);
					  return NUM;
					}
{ROLENAME}				{
					  learnlval.string = strdup(yytext);
					  return ROLENAME;
					}
{FILENAME}				{
					  learnlval.string = strdup(yytext);
					  return FILENAME;
					}
{IPADDR}				{
					  learnlval.string = strdup(yytext);
					  return IPADDR;
					}
:					{ return ':'; }
.					;
%%

void learnerror(const char *s) { return; }
int learnwrap(void) { return 1; }

void parse_learn_log(const char * filename)
{
	FILE * file;
	
	file = fopen(filename, "r");

	if(!file) {
		fprintf(stderr, "Unable to open %s.\n"
				"Error: %s\n", filename, strerror(errno));
		exit(EXIT_FAILURE);
	}
	
	learn_db = (struct learn_info **) calloc(1, sizeof(struct learn_info *));
	learn_num = 0;

	if(!learn_db)
		failure("calloc");

	ip_learn_db = (struct ip_learn_info **) calloc(1, sizeof(struct ip_learn_info *));
	ip_learn_num = 0;

	if(!ip_learn_db)
		failure("calloc");

	learnin = file;
	learnparse();

	fclose(file);
	return;
}
