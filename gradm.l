%{
#include "gradm.h"
#include "gradm.tab.h"

unsigned long lineno;
char *gr_line;
unsigned int old_state;
unsigned int old_state2;

int gradmerror(char *s);
int gradmwrap(void);
int is_eof(void);
void add_include(char *includename);

struct include_entry {
	unsigned long lineno;
	YY_BUFFER_STATE buffer;
	FILE *file;
	char *name;
	struct include_entry *prev;
	struct include_entry *next;
	struct include_entry *parent;
	struct include_entry **stack;
	int sp;
};

struct include_entry include_stack;
struct include_entry *current_stack;

%}

IP [0-9]{1,3}"."[0-9]{1,3}"."[0-9]{1,3}"."[0-9]{1,3}

%option nounput

%x ROLE_STATE SUBJECT_STATE IP_STATE RES_STATE COMMENT_STATE ROLETYPE_STATE
%x INCLUDE_STATE IPNETMASK_STATE IPPORT_STATE ROLETRANS_STATE
%x VAR_STATE VAR_OBJ_STATE IDTRANS_STATE DOMAIN_STATE DOMAINTYPE_STATE
%x DOMAINLIST_STATE

%%

<*>"\n"					{
					  lineno++;
					  if (YYSTATE == COMMENT_STATE)
						  BEGIN(old_state2);
					  if (YYSTATE != VAR_STATE && YYSTATE != VAR_OBJ_STATE)
						  BEGIN(INITIAL);
					}
<*>"#"					{
					  if (YYSTATE != COMMENT_STATE)
						  old_state2 = YYSTATE;
					  BEGIN(COMMENT_STATE);
					}
<*>[ \t]+				;
<COMMENT_STATE>.*			;

<ROLETYPE_STATE>[ugslGNAT]*		{
					  gradmlval.shortnum = role_mode_conv(yytext);
					  return ROLE_TYPE;
					}
<DOMAINTYPE_STATE>([ug]l?)|(l?[ug])	{
					  BEGIN(DOMAINLIST_STATE);
					  gradmlval.string = gr_strdup(yytext);
					  return DOMAIN_TYPE;
					}
<ROLE_STATE>[_a-zA-Z0-9-]{1,30}		{
					  BEGIN(ROLETYPE_STATE);
					  gradmlval.string = gr_strdup(yytext);
					  return ROLE_NAME;
					}
<DOMAIN_STATE>[_a-zA-Z0-9-]{1,30}	{
					  BEGIN(DOMAINTYPE_STATE);
					  gradmlval.string = gr_strdup(yytext);
					  return ROLE_NAME;
					}
<DOMAINLIST_STATE>[_a-zA-Z0-9-]{1,30}	{
					  gradmlval.string = gr_strdup(yytext);
					  return ROLE_NAME;
					}
<ROLETRANS_STATE>[_a-zA-Z0-9-]{1,30}	{
					  gradmlval.string = gr_strdup(yytext);
					  return ROLE_NAME;
					}

<SUBJECT_STATE>":"			{ 
					  return ':';
					}
<SUBJECT_STATE>[/][^ :\t\n]*		{ 
					  gradmlval.string = gr_strdup(yytext);
					  return SUBJ_NAME;
					}
<SUBJECT_STATE>["][/][^:\n]*["]		{
					  gr_line = yytext;
					  gr_line++;
					  *(gr_line + strlen(gr_line) - 1) = '\0';
					  gradmlval.string = gr_strdup(gr_line);
					  return SUBJ_NAME;
					}
<SUBJECT_STATE>$HOME[/]?[^ :\t\n]*	{ 
					  gradmlval.string = gr_strdup(yytext);
					  return SUBJ_NAME;
					}
<SUBJECT_STATE>["]$HOME[/]?[^:\n]*["]		{
					  gr_line = yytext;
					  gr_line++;
					  *(gr_line + strlen(gr_line) - 1) = '\0';
					  gradmlval.string = gr_strdup(gr_line);
					  return SUBJ_NAME;
					}
<SUBJECT_STATE>[TKCAPRMSGXOolhpkvdbri]+	{
					  gradmlval.num = proc_subject_mode_conv(yytext);
					  return SUBJ_MODE;
					}

<RES_STATE>"unlimited"			{
					  gradmlval.string = gr_strdup(yytext);
					  return RES_SOFTHARD;
					}
<RES_STATE>[0-9]+[smhdKMG]?		{
					  gradmlval.string = gr_strdup(yytext);
					  return RES_SOFTHARD;
					}

<IP_STATE>"disabled"			{
					  return DISABLED;
					}
<IP_STATE>{IP}				{
					  gradmlval.num = get_ip(yytext);
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
					  gradmlval.string = gr_strdup(yytext);
					  return IPTYPE;
					}
<IP_STATE>[a-z_-]+			{
					  gradmlval.string = gr_strdup(yytext);
					  return IPPROTO;
					}

<IPNETMASK_STATE>[0-9]{1,2}		{
					  unsigned int bits = atoi(yytext);
					  BEGIN(IP_STATE);
					  if (!bits)
						gradmlval.num = 0;
					  else
						gradmlval.num = 0xffffffff << (32 - bits);
					  return IPNETMASK;
					}
<IPPORT_STATE>[0-9]{1,5}		{
					  BEGIN(IP_STATE);
					  gradmlval.shortnum = atoi(yytext);
					  return IPPORT;
					}

"define"				{
					  old_state = YYSTATE;
					  BEGIN(VAR_STATE);
					  return DEFINE;
					}
[$][a-zA-Z0-9_]+			{
					  gr_line = yytext;
					  gr_line++;
					  gradmlval.string = gr_strdup(gr_line);
					  if (!strcmp(gr_line, "HOME"))
						return OBJ_NAME;
					  else
					  	return VARIABLE;
					}
<VAR_STATE>[a-zA-Z0-9_]+		{
					  gradmlval.string = gr_strdup(yytext);
					  return DEFINE_NAME;
					}
<VAR_STATE>"{"				{
					  BEGIN(VAR_OBJ_STATE);
					  return '{';
					}
<VAR_OBJ_STATE>"}"			{
					  BEGIN(old_state);
					  return '}';
					}
<VAR_OBJ_STATE>[/][^ \t\n]*		{
					  gradmlval.string = gr_strdup(yytext);
					  return OBJ_NAME;
					}
<VAR_OBJ_STATE>["][/].*["]		{
					  gr_line = yytext;
					  gr_line++;
					  *(gr_line + strlen(gr_line) - 1) = '\0';
					  gradmlval.string = gr_strdup(gr_line);
					  return OBJ_NAME;
					}
<VAR_OBJ_STATE>[rwxahitmlLFRWXAIMdDcCspo]+	{
					  gradmlval.num = proc_object_mode_conv(yytext);
					  return OBJ_MODE;
					}
<IDTRANS_STATE>[_a-zA-Z0-9-]{1,30}	{
					  gradmlval.string = gr_strdup(yytext);
					  return ID_NAME;
					}
"user_transition_allow"			{
					  BEGIN(IDTRANS_STATE);
					  return USER_TRANS_ALLOW;
					}
"user_transition_deny"			{
					  BEGIN(IDTRANS_STATE);
					  return USER_TRANS_DENY;
					}
"group_transition_allow"		{
					  BEGIN(IDTRANS_STATE);
					  return GROUP_TRANS_ALLOW;
					}
"group_transition_deny"			{
					  BEGIN(IDTRANS_STATE);
					  return GROUP_TRANS_DENY;
					}
"role"					{
					  BEGIN(ROLE_STATE);
					  return ROLE;
					}
"domain"				{
					  BEGIN(DOMAIN_STATE);
					  return DOMAIN;
					}
"role_allow_ip"				{
					  BEGIN(IP_STATE);
					  return ROLE_ALLOW_IP;
					}
"role_transitions"			{
					  BEGIN(ROLETRANS_STATE);
					  return ROLE_TRANSITION;
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
"include"[ \t]*[<][/].*[>]		{
					  gr_line = strchr(yytext, '/');
					  *(gr_line + strlen(gr_line) - 1) = '\0';
					  add_include(gr_line);					  
					}
[+-]"CAP_"[_A-Z]+			{
					  gradmlval.string = gr_strdup(yytext);
					  return CAP_NAME;
					}
"RES_"[A-Z]+				{
					  BEGIN(RES_STATE);
					  gradmlval.string = gr_strdup(yytext);
					  return RES_NAME;
					}

[/][^ \t\n]*				{
					  gradmlval.string = gr_strdup(yytext);
					  return OBJ_NAME;
					}
["][/].*["]				{
					  gr_line = yytext;
					  gr_line++;
					  *(gr_line + strlen(gr_line) - 1) = '\0';
					  gradmlval.string = gr_strdup(gr_line);
					  return OBJ_NAME;
					}
$HOME[/]?[^ \t\n]*			{
					  gradmlval.string = gr_strdup(yytext);
					  return OBJ_NAME;
					}
["]$HOME[/]?.*["]			{
					  gr_line = yytext;
					  gr_line++;
					  *(gr_line + strlen(gr_line) - 1) = '\0';
					  gradmlval.string = gr_strdup(gr_line);
					  return OBJ_NAME;
					}
[rwxahitmlLFRWXAIMcCdDspo]+		{
					  gradmlval.num = proc_object_mode_conv(yytext);
					  return OBJ_MODE;
					}
[|&()-]					{
						return *yytext;
					}
[{}]					;
<<EOF>>					{
					  if (is_eof())
						yyterminate();
					}
.					{ gradmerror("invalid character"); }

%%

void add_include(char *includename)
{
	struct stat fstat;
	FILE *tmpfile;

	if (current_stack->sp >= MAX_INCLUDE_DEPTH) {
		fprintf(stderr, "Includes too deep while trying to process "
				"%s\n", includename);
		exit(EXIT_FAILURE);
	}

	current_stack->stack = realloc(current_stack->stack, (1 + current_stack->sp) * sizeof(struct include_entry *));
	if (current_stack->stack == NULL)
		failure("realloc");
	current_stack->stack[current_stack->sp] = calloc(1, sizeof(struct include_entry));
	if (current_stack->stack[current_stack->sp] == NULL)
		failure("calloc");
	current_stack->stack[current_stack->sp]->lineno = lineno;
	lineno = 1;
	current_stack->stack[current_stack->sp]->file = yyin;
	current_stack->stack[current_stack->sp]->name = current_acl_file;
	current_stack->stack[current_stack->sp]->buffer = YY_CURRENT_BUFFER;
	current_stack->stack[current_stack->sp]->parent = current_stack;

	if (!stat(includename, &fstat)) {
		if (S_ISDIR(fstat.st_mode)) {
			struct dirent **namelist;
			struct include_entry *last = current_stack->stack[current_stack->sp];
			struct include_entry *tmp = NULL;
			char *path;
			int n;

			n = scandir(includename, &namelist, 0, alphasort);
			if (n >= 3) {
				while (n--) {
					if (!strcmp(namelist[n]->d_name, ".") || !strcmp(namelist[n]->d_name, ".."))
						continue;
					tmp = calloc(1, sizeof(struct include_entry));
					if (tmp == NULL)
						failure("calloc");
					
					path = calloc(1, strlen(includename) + strlen(namelist[n]->d_name) + 2);
					if (path == NULL)
						failure("calloc");

					sprintf(path, "%s/%s", includename, namelist[n]->d_name);

					tmp->name = path;
					tmp->lineno = 1;
					tmp->parent = current_stack;

					last->next = tmp;
					tmp->prev = last;
					last = tmp;
				}
				change_current_acl_file(tmp->name);
				tmpfile = fopen(tmp->name, "r");

				if (!tmpfile) {
					fprintf(stderr, "Unable to open included file: %s\n", tmp->name);
					exit(EXIT_FAILURE);
				}

				yyin = tmpfile;
				current_stack = tmp;
				yy_switch_to_buffer(yy_create_buffer(yyin, YY_BUF_SIZE));
				return;
			}
			return;
		}
	}
	tmpfile = fopen(includename, "r");

	if (!tmpfile) {
		fprintf(stderr, "Unable to open included file: %s\n",
			includename);
		exit(EXIT_FAILURE);
	}

	change_current_acl_file(includename);
	current_stack->sp++;
	yyin = tmpfile;
	yy_switch_to_buffer(yy_create_buffer(yyin, YY_BUF_SIZE));

	return;
}

int is_eof(void)
{
	if (current_stack->sp)
		fclose(yyin);
	current_stack->sp--;
	if (current_stack->sp < 0) {
		if (!current_stack->prev || !current_stack->prev->prev) {
			if (current_stack->parent == NULL) {
				current_stack->sp = 0;
				lineno = 1;
				return 1;
			} else {
				current_stack = current_stack->parent;
				if (current_stack->prev != NULL)
					current_stack = current_stack->prev;
				goto regular;
			}
		} else {
			current_stack = current_stack->prev;
			lineno = 1;
			change_current_acl_file(current_stack->name);
			yy_delete_buffer(YY_CURRENT_BUFFER);
			yyin = fopen(current_stack->name, "r");
			if (yyin == NULL) {
				fprintf(stderr, "Unable to open included file: %s\n", current_stack->name);
				exit(EXIT_FAILURE);
			}
			yy_switch_to_buffer(yy_create_buffer(yyin, YY_BUF_SIZE));
			return 0;
		}
	}

regular:
	change_current_acl_file(current_stack->stack[current_stack->sp]->name);
	yy_delete_buffer(YY_CURRENT_BUFFER);
	lineno = current_stack->stack[current_stack->sp]->lineno;
	yyin = current_stack->stack[current_stack->sp]->file;
	yy_switch_to_buffer(current_stack->stack[current_stack->sp]->buffer);

	return 0;
}

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

#ifdef GRADM_DEBUG
void show_policy(void) {
	struct file_acl *filp;
	struct ip_acl *ipp;
	struct proc_acl *proc;
	struct role_acl *rolp;
	struct role_transition *rolet;
	extern struct rlimconv rlim_table[];
	int i;

	for (rolp = current_role;rolp;rolp=rolp->prev) {
	printf("ROLE: %s type:%s uid/gid:%u\n", rolp->rolename,
		rolp->roletype & GR_ROLE_SPECIAL ? "special" :
		rolp->roletype & GR_ROLE_USER ? "user" :
		rolp->roletype & GR_ROLE_GROUP ? "group" :
		rolp->roletype & GR_ROLE_DEFAULT ? "default" : "",
		rolp->uidgid);
	printf("\tTRANSITIONS:");
	for (rolet = rolp->transitions; rolet; rolet=rolet->prev)
		printf(" %s", rolet->rolename);
	printf("\n");
	for (proc = rolp->hash->first;proc;proc=proc->prev) {
		printf("\tSUBJECT: %s dev:%d inode:%lu mode:%d c_raise:%x c_drop:%x\n",
			proc->filename, proc->dev, proc->inode, proc->mode, ~proc->cap_drop,
			proc->cap_drop);
		for (i = 0; i < proc->ip_num; i++) {
			char ipaddr[4];
			int c;
			int netmask = 0;

			ipp = *(proc->ips + i);
			memcpy(&ipaddr, &(ipp->addr), sizeof(ipaddr));
			for (c = 0; c < 32; c++)
				if (ipp->addr & (1 << c))
					netmask++;
			if (ipp->mode == GR_IP_CONNECT)
				printf("\tCONNECT %u.%u.%u.%u/%u:%d-%d", ipaddr[0], ipaddr[1], ipaddr[2], ipaddr[3], netmask, ipp->low, ipp->high);
			else
				printf("\tBIND %u.%u.%u.%u/%u:%d-%d", ipaddr[0], ipaddr[1], ipaddr[2], ipaddr[3], netmask, ipp->low, ipp->high);

			for (c = 1; c < 5; c++) {
				if (ipp->type & (1 << c)) {
					switch (c) {
					case SOCK_RAW:
						printf(" raw_sock");
						break;
					case SOCK_DGRAM:
						printf(" dgram");
						break;
					case SOCK_STREAM:
						printf(" stream");
						break;
					case SOCK_RDM:
						printf(" rdm");
						break;
					}
				}
			}
			for (c = 0; c < 256; c++) {
				if (ipp->proto[c / 32] & (1 << (c % 32))) {
					if (c == IPPROTO_RAW)
						printf(" raw_proto");
					else {
						struct protoent *proto;
						proto = getprotobynumber(c);
						printf(" %s", proto->p_name);
					}
				}
			}
			printf("\n");
		}
		for (filp = proc->hash->first;filp;filp=filp->prev)
                        printf("\t\tOBJECT: %s dev:%d inode:%lu mode:%d\n", filp->filename, filp->dev, filp->inode, filp->mode);
		for (i=0;i<GR_NLIMITS;i++)
			if (proc->resmask & (1 << i))
				printf("\t\t%s: soft: %lu hard: %lu\n", rlim_table[i].name, proc->res[i].rlim_cur, proc->res[i].rlim_max);
	}
	}
}
#endif

int main(int argc, char *argv[])
{
	if (geteuid() != getuid()) {
		fprintf(stderr, "gradm is not meant to run suid root.\n");
		exit(EXIT_FAILURE);
	}

	special_role_uid = 0;
	
	no_coredump();

	current_stack = &include_stack;
	memset(current_stack, 0, sizeof(struct include_entry));

	init_variables();

	parse_args(argc, argv);

#ifdef GRADM_DEBUG
	show_policy();
#endif
	return 0;
}

