%{
#include "gradm.h"
#include "gradm.tab.h"

unsigned long lineno = 1;
char *gr_line;

int gradmerror(char *s);
int gradmwrap(void);
%}

IP [0-9]{1,3}"."[0-9]{1,3}"."[0-9]{1,3}"."[0-9]{1,3}

%option nounput

%x ROLE_STATE SUBJECT_STATE IP_STATE RES_STATE COMMENT_STATE ROLETYPE_STATE
%x INCLUDE_STATE IPNETMASK_STATE IPPORT_STATE

%%

<*>"\n"					{
					  lineno++;
					  BEGIN(INITIAL);
					}
<*>"#"					{ BEGIN(COMMENT_STATE); }
<*>[ \t]+				;
<COMMENT_STATE>[.]*			;

<ROLETYPE_STATE>[ug]			{
					  gradmlval.string = strdup(yytext);
					  return ROLE_TYPE;
					}
<ROLE_STATE>[_a-zA-Z0-9-]+		{
					  BEGIN(ROLETYPE_STATE);
					  gradmlval.string = strdup(yytext);
					  return ROLE_NAME;
					}

<SUBJECT_STATE>[/][^ \t\n]*		{
					  gradmlval.string = strdup(yytext);
					  return SUBJ_NAME;
					}
<SUBJECT_STATE>["][/].*["]		{
					  gr_line = yytext;
					  gr_line++;
					  *(gr_line + strlen(gr_line) - 1) = '\0';
					  gradmlval.string = strdup(gr_line);
					  return SUBJ_NAME;
					}
<SUBJECT_STATE>[TKCAPRMSGXOolhpkv]+	{
					  gradmlval.string = strdup(yytext);
					  return SUBJ_MODE;
					}

<RES_STATE>"unlimited"			{
					  gradmlval.string = strdup(yytext);
					  return RES_SOFTHARD;
					}
<RES_STATE>[0-9]+[smhdKMG]?		{
					  gradmlval.string = strdup(yytext);
					  return RES_SOFTHARD;
					}

<IP_STATE>{IP}				{
					  gradmlval.string = strdup(yytext);
					  return IPADDR;
					}
<IP_STATE>[/]				{
					  BEGIN(IPNETMASK_STATE);
					  return *yytext;
					}
<IP_STATE>[:-]				{
					  BEGIN(IPPORT_STATE);
					  return *yytext;
					}
<IP_STATE>"raw_sock"|"dgram"|"rdm"|"stream"|"any_sock" {
					  gradmlval.string = strdup(yytext);
					  return IPTYPE;
					}
<IP_STATE>[a-z]+			{
					  gradmlval.string = strdup(yytext);
					  return IPPROTO;
					}

<IPNETMASK_STATE>[0-9]{1,2}		{
					  BEGIN(IP_STATE);
					  gradmlval.string = strdup(yytext);
					  return IPNETMASK;
					}
<IPPORT_STATE>[0-9]{1,5}		{
					  BEGIN(IP_STATE);
					  gradmlval.string = strdup(yytext);
					  return IPPORT;
					}

<INCLUDE_STATE>[<][/].*[>]		{
					  gr_line = yytext;
					  gr_line++;
					  *(gr_line + strlen(gr_line) - 1) = '\0';
					  gradmlval.string = strdup(gr_line);
					  return INCLUDE_NAME;
					}

"role"					{
					  BEGIN(ROLE_STATE);
					  return ROLE;
					}
"subject"				{
					  BEGIN(SUBJECT_STATE);
					  return SUBJECT;
					}
"connect"				{
					  BEGIN(IP_STATE);
					  return CONNECT;
					}
"bind"					{
					  BEGIN(IP_STATE);
					  return BIND;
					}
"include"				{
					  BEGIN(INCLUDE_STATE);
					  return INCLUDE;
					}
[+-]"CAP_"[_A-Z]+			{
					  gradmlval.string = strdup(yytext);
					  return CAP_NAME;
					}
"RES_"[A-Z]+				{
					  BEGIN(RES_STATE);
					  gradmlval.string = strdup(yytext);
					  return RES_NAME;
					}

[/][^ \t\n]*				{
					  gradmlval.string = strdup(yytext);
					  return OBJ_NAME;
					}
["][/].*["]				{
					  gr_line = yytext;
					  gr_line++;
					  *(gr_line + strlen(gr_line) - 1) = '\0';
					  gradmlval.string = strdup(gr_line);
					  return OBJ_NAME;
					}
[rwxahitFRWXAITo]+			{
					  gradmlval.string = strdup(yytext);
					  return OBJ_MODE;
					}

%%

int gradmwrap(void)
{
	return 1;
}

int gradmerror(char *s)
{
	fflush(stderr);  
	fprintf(stderr, "\"%s\" caused a %s on line %lu of %s\n", yytext, s,
		lineno, current_acl_file);
	exit(EXIT_FAILURE);
}

void no_coredump(void)
{
	struct rlimit rlim;

	rlim.rlim_cur = 0;
	rlim.rlim_max = 0;

	setrlimit(RLIMIT_CORE, &rlim);

	return;
}

int main(int argc, char *argv[])
{
#ifdef GRADM_DEBUG
	struct file_acl *filp;
	struct proc_acl *proc;
	struct role_acl *rolp;
	extern struct rlimconv rlim_table[];
	int i;
#endif
	no_coredump();

	init_variables();

	parse_args(argc, argv);

#ifdef GRADM_DEBUG
	for (rolp = current_role;rolp;rolp=rolp->prev) {
	printf("ROLE: %s type:%s uid/gid:%u\n", rolp->rolename,
		rolp->roletype & GR_ROLE_USER ? "user" :
		rolp->roletype & GR_ROLE_GROUP ? "group" :
		rolp->roletype & GR_ROLE_DEFAULT ? "default" : "",
		rolp->uidgid);
	for (proc = rolp->proc_subject;proc;proc=proc->prev) {
		printf("\tSUBJECT: %s dev:%d inode:%lu mode:%d c_raise:%x c_drop:%x\n",
			proc->filename, proc->dev, proc->inode, proc->mode, proc->cap_raise,
			proc->cap_drop);
		for (filp = proc->proc_object;filp;filp=filp->prev)
                        printf("\t\tOBJECT: %s dev:%d inode:%lu mode:%d\n", filp->filename, filp->dev, filp->inode, filp->mode);
		for (i=0;i<GR_NLIMITS;i++)
			if (proc->resmask & (1 << i))
				printf("\t\t%s: soft: %lu hard: %lu\n", rlim_table[i].name, proc->res[i].rlim_cur, proc->res[i].rlim_max);
	}
	}
#endif
	return 0;
}
