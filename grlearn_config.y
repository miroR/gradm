%{
#include "gradm.h"
extern int grlearn_configlex(void);
%}

%union {
	char * string;
	unsigned long num;
}

%token <string> FILENAME NOLEARN INHERITLEARN INHERITNOLEARN CACHESIZE
%token <num> NUM

%%

learn_config_file:	learn_config
		|	learn_config_file learn_config
		;

learn_config:
		NOLEARN FILENAME
		{
			add_proc_subject_acl(current_role, $2, proc_subject_mode_conv("o"), 0);
			add_proc_object_acl(current_subject, "/", proc_object_mode_conv("rwxcdm"), GR_FEXIST);
		}
	|	INHERITLEARN FILENAME
		{
			struct ip_acl ip;

			add_proc_subject_acl(current_role, $2, proc_subject_mode_conv("oi"), 0);
			add_proc_object_acl(current_subject, "/", proc_object_mode_conv("h"), GR_FEXIST);
			add_cap_acl(current_subject, "-CAP_ALL");

			memset(&ip, 0, sizeof (ip));
			add_ip_acl(current_subject, GR_IP_CONNECT, &ip);
			add_ip_acl(current_subject, GR_IP_BIND, &ip);
		}
	|	INHERITNOLEARN FILENAME
		{
			add_proc_subject_acl(current_role, $2, proc_subject_mode_conv("o"), 0);
			add_proc_object_acl(current_subject, "/", proc_object_mode_conv("rwxcdmi"), GR_FEXIST);
		}
	|	CACHESIZE NUM
	;
%%
