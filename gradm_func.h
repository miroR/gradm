void yyerror(const char *s);
FILE *open_acl_file(const char *filename);
void get_user_passwd(struct gr_pw_entry *entry, int mode);
int transmit_to_kernel(void *buf, unsigned long len);
void generate_salt(struct gr_pw_entry *entry);
void write_user_passwd(struct gr_pw_entry *entry);
void parse_acls(void);
void analyze_acls(void);
void generate_hash(struct gr_pw_entry *entry);
void init_variables(void);
void parse_args(int argc, char *argv[]);
__u32 cap_conv(const char *cap);
__u32 file_mode_conv(const char *mode);
__u32 proc_subject_mode_conv(const char *mode);
__u32 proc_object_mode_conv(const char *mode);
int add_proc_subject_acl(struct role_acl *role, char *filename, __u32 mode, int flag);
int add_proc_object_acl(struct proc_acl *subject, char *filename,
			__u32 mode, int type);
void add_cap_acl(struct proc_acl *subject, const char *cap);
void add_gradm_acl(struct role_acl *role);
void add_grlearn_acl(struct role_acl *role);
void change_current_acl_file(const char *filename);
struct gr_arg *conv_user_to_kernel(struct gr_pw_entry *entry);
int parent_dir(const char *filename, char *parent_dirent[]);
void rem_proc_object_acl(struct proc_acl *proc, struct file_acl *filp);
void expand_acls(void);
int test_perm(const char *obj, const char *subj);
void add_res_acl(struct proc_acl *subject, const char *name,
		 const char *soft, const char *hard);
void pass_struct_to_human(FILE * stream);
void syslog_lookup_log(char **learnlog);
int is_valid_elf_binary(const char *filename);
void handle_learn_logs(const char *logfile, FILE * stream);
void modify_caps(struct proc_acl *proc, int cap);
void modify_res(struct proc_acl *proc, int res, unsigned long cur,
		unsigned long max);
void add_ip_acl(struct proc_acl *subject, __u8 mode, struct ip_acl *tmp);
void parse_learn_log(const char *filename);
void add_learn_ip_info(char *rolename, __u16 roletype, char *subjname,
		       __u32 ip, __u16 port, __u16 sock, __u16 proto,
		       __u16 mode);
void add_learn_file_info(char *rolename, __u16 roletype, char *subjname,
			 unsigned long res_cur, unsigned long res_max,
			 char *obj_name, __u32 mode);
int read_saltandpass(char *rolename, unsigned char *salt, unsigned char *pass);
void add_kernel_acl(void);
int add_role_acl(struct role_acl **role, char *rolename, __u16 type,
		 int ignore);
__u16 role_mode_conv(const char *mode);
__u32 get_ip(char *p);
void conv_name_to_type(struct ip_acl *ip, char *name);
void add_role_allowed_ip(struct role_acl *role, __u32 addr, __u32 netmask);
void add_role_transition(struct role_acl *role, char *rolename);
void add_proc_nested_acl(struct role_acl *role, char *mainsubjname, char **nestednames, int nestlen, __u32 nestmode);
void start_grlearn(char *logfile);
void stop_grlearn(void);
