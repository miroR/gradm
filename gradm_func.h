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
int is_valid_elf_binary(const char *filename);
void handle_learn_logs(const char *logfile, FILE * stream);
void modify_caps(struct proc_acl *proc, int cap);
void modify_res(struct proc_acl *proc, int res, unsigned long cur,
		unsigned long max);
void add_ip_acl(struct proc_acl *subject, __u8 mode, struct ip_acl *tmp);
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
void sym_store(char *symname, struct var_object *object);
struct var_object *sym_retrieve(char *symname);
void add_var_object(struct var_object **object, char *name, __u32 mode);
void interpret_variable(struct var_object *var);
struct var_object *union_objects(struct var_object *var1, struct var_object *var2);
struct var_object *intersect_objects(struct var_object *var1, struct var_object *var2);
struct var_object *differentiate_objects(struct var_object *var1, struct var_object *var2);
void sort_file_list(struct gr_learn_file_tmp_node **file_list);
void insert_temp_file(struct gr_learn_file_tmp_node ***file_list, char *filename, __u32 mode);
struct gr_learn_file_node *match_file_node(struct gr_learn_file_node *base, const char *filename);
void match_role(struct gr_learn_group_node **grouplist, uid_t uid, gid_t gid, struct gr_learn_group_node **group, struct gr_learn_user_node **user);
struct gr_learn_ip_node ** find_insert_ip(struct gr_learn_ip_node **base, __u32 ip, struct gr_learn_ip_node **parent);
void conv_mode_to_str(__u32 mode, char *modestr, unsigned short len);
void conv_subj_mode_to_str(__u32 mode, char *modestr, unsigned short len);
void generate_full_learned_acls(char *learn_log, FILE *stream);
void reduce_roles(struct gr_learn_group_node ***grouplist);
void insert_file(struct gr_learn_file_node **base, char *filename, __u32 mode, __u8 subj);
void first_stage_reduce_tree(struct gr_learn_file_node *base);
void second_stage_reduce_tree(struct gr_learn_file_node *base);
void third_stage_reduce_tree(struct gr_learn_file_node *base);
void traverse_roles(struct gr_learn_group_node **grouplist,
		int (*act)(struct gr_learn_group_node *group, struct gr_learn_user_node *user, FILE *stream),
		FILE *stream);
void traverse_file_tree(struct gr_learn_file_node *base,
		int (*act)(struct gr_learn_file_node *node, struct gr_learn_file_node *optarg, FILE *stream),
		struct gr_learn_file_node *optarg, FILE *stream);
void reduce_ip_tree(struct gr_learn_ip_node *base);
void reduce_ports_tree(struct gr_learn_ip_node *base);
void display_roles(struct gr_learn_group_node **grouplist, FILE *stream);
void add_fulllearn_acl(void);
void insert_ip(struct gr_learn_ip_node **base, __u32 ip, __u16 port, __u8 proto,
		__u8 socktype);
int is_protected_path(char *filename, __u32 mode);

struct gr_learn_role_entry *
insert_learn_role(struct gr_learn_role_entry ***role_list, char *rolename, __u16 rolemode);
struct gr_learn_role_entry *
find_learn_role(struct gr_learn_role_entry **role_list, char *rolename);
int full_reduce_object_node(struct gr_learn_file_node *subject,
			    struct gr_learn_file_node *unused1,
			    FILE *unused2);
void
conv_role_mode_to_str(__u16 mode, char *modestr, unsigned short len);
int full_reduce_ip_node(struct gr_learn_file_node *subject,
			struct gr_learn_file_node *unused1,
			FILE *unused2);
void display_ip_tree(struct gr_learn_ip_node *base, __u8 contype, FILE *stream);
int display_only_ip(struct gr_learn_ip_node *node, struct gr_learn_ip_node **unused, __u8 unused2,
		    FILE *stream);
void traverse_ip_tree(struct gr_learn_ip_node *base,
			struct gr_learn_ip_node **optarg,
			int (*act)(struct gr_learn_ip_node *node, struct gr_learn_ip_node **optarg, __u8 contype, FILE *stream),
			__u8 contype, FILE *stream);
void display_tree(struct gr_learn_file_node *base, FILE *stream);
void enforce_high_protected_paths(struct gr_learn_file_node *subject);
void insert_user(struct gr_learn_group_node ***grouplist, char *username, char *groupname, uid_t uid, gid_t gid);
void add_rolelearn_acl(void);
int ensure_subject_security(struct gr_learn_file_node *subject,
			struct gr_learn_file_node *unused1,
			FILE *unused2);

void check_acl_status(__u16 reqmode);
struct file_acl *lookup_acl_object_by_name(struct proc_acl *subject, char *name);
struct proc_acl *lookup_acl_subject_by_name(struct role_acl *role, char *name);
struct file_acl *lookup_acl_object(struct proc_acl *subject, struct file_acl *object);
struct proc_acl *lookup_acl_subject(struct role_acl *role, struct proc_acl *subject);

void * gr_dyn_alloc(unsigned long len);
void * gr_stat_alloc(unsigned long len);
void * gr_dyn_realloc(void *addr, unsigned long len);

void insert_acl_object(struct proc_acl *subject, struct file_acl *object);
void insert_acl_subject(struct role_acl *role, struct proc_acl *subject);

