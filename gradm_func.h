void yyerror(const char *s);
//Pre: error message as string
//Post: prints the error message returned by yacc

FILE *open_acl_file(const char *filename);
//Pre: filename as string
//Post: existence of file is checked, file is opened for read access
//      and returned as a file struct

void get_user_passwd(struct gr_pw_entry *entry, int mode);
//Pre: gr_pw_entry struct (can be empty) and a valid mode (0 or 1)
//Post: the gr_pw_entry struct is filled with values depending on the
//      mode chosen.  It can be GR_PWONLY or GR_PWANDSUM.  In the latter
//      case, the password is entered twice for verification, a random 
//      salt is chosen, and the SHA1 sum is computed.
//      This mode is only used for password generation, and is written
//      to /etc/grsec/pw.  In the other mode, the password is simply
//      written to the structure, and is then sent on to the kernel
//      for any kernel operations (except init mode) that are initiated 

void transmit_to_kernel(void *buf, unsigned long len);
//Pre: pointer to a region of memory, length of memory to send to kernel
//Post: writes len bytes of data from pointer buf to the kernel.
//      an error is generated if bytes written != len or if
//      /proc/sys/kernel/grsecurity/acl

void generate_salt(struct gr_pw_entry *entry);
//Pre: gr_pw_entry structure (possibly empty)
//Post: GR_SALT_SIZE bytes are read from /dev/random and stored
//      in the salt member of gr_pw_entry

void write_user_passwd(struct gr_pw_entry *entry);
//Pre: gr_pw_entry with SHA1 sum and salt filled out
//Post: salt and sum are written to /etc/grsec/pw

void parse_acls(void);
//Pre: none
//Post: initiates parsing of the main acl config, and handles parsing of
//      all included acl configs

void analyze_acls(void);
//Pre: none
//Post: checks for common mistakes in acl files.  We do this before
//      sending the data off to the kernel with transmit_to_kernel()
//      currently checks to see if a default acl is not present

void generate_hash(struct gr_pw_entry *entry);
//Pre: gr_pw_entry with password and salt filled out
//Post: salt is prepended to the password, hashed with SHA1 and stored
//      in the sum member of gr_pw_entry

void init_variables(void);
//Pre: none
//Post: initializes line number, cap_raise_tmp, cap_drop_tmp,
//      and main linked lists

void parse_args(int argc, char *argv[]);
//Pre: array of argument pointers and number of args
//Post: handles options passed to gradm.

__u32 cap_conv(const char *cap);
//Pre: capability name as string
//Post: returns value of capability as determined by capability.h

__u32 file_mode_conv(const char *mode);
//Pre: string (possibly null) of mode characters for file acls
//Post: returns the or'd value of all the modes on success
//      prints error message and quits on failure
//      fails when character in mode string is not a valid file acl mode

__u32 proc_subject_mode_conv(const char *mode);
//Pre: string (possibly null) of mode characters for proc acl subjects
//Post: returns the or'd value of all the modes on success
//      prints error message and quits on failure
//      fails when character in mode string is not valid proc acl subject mode

__u32 proc_object_mode_conv(const char *mode);
//Pre: string (possibly null) of mode characters for proc acl objects
//Post: returns the or'd value of all the modes on success
//      prints error message and quits on failure
//      fails when character in mode string is not valid proc acl object mode

int add_proc_subject_acl(struct role_acl *role, char *filename, __u32 mode);
//Pre: filename as string, mode as string, type as integer, struct acl_tmps
//Post: adds a new process acl to the current linked list of process acls
//      this function is called after all the other functions related
//      to adding data to proc acls, namely the two functions below
//      after creation of process acl, cap_raise_tmp and cap_drop_tmp
//      are zeroed, and gr_file_tmp is set to NULL (so a new linked list is
//      created next time) linked list works in such a way that ->next 
//      points to the previously entered acl 
//      type determines whether the current acl has the subject checked
//      if its on the filesystem.  we change the type for the admin
//      acl, since it does not belong to a single file.

int add_proc_object_acl(struct proc_acl *subject, char *filename,
			__u32 mode, int type);
//Pre: filename as string, mode as string, linked list of files
//Post: adds a process acl object to the temporary linked list
//      of process acl objects, to be inserted when the process acl 
//      subject is found. type specifies whether or not the object being
//      added was created during learning mode

void add_cap_acl(struct proc_acl *subject, const char *cap);
//Pre: capability (including the + or -) as string
//Post: or's the current value of cap_raise and cap_drop for the current 
//      process acl with that derived from capability.h through 
//      converting the capability argument to its integer equivalent.

void add_gradm_acl(struct role_acl *role);
//Pre: none
//Post: adds the acl for gradm: very restrictive

void change_current_acl_file(const char *filename);
//Pre: filename as string
//Post: frees current_acl_file and mallocs a new one with size strlen(filename)

struct gr_arg *conv_user_to_kernel(struct gr_pw_entry *entry);
//Pre: filled out gr_pw_entry struct, used to copy passwd to gr_arg
//Post: allocates memory roughly the size of all the process subjects and
//      objects, and fills in the gr_arg structure

int parent_dir(const char *filename, char *parent_dirent[]);
//Pre: filename to check for /'s, parent_dir to store parent directory in
//      parent_dir must contain a copy of filename before being called
//Post: returns 1 if a parent directory was stored, 0 if not.  parent_dir 
//      holds the parent directory

void rem_proc_object_acl(struct proc_acl *proc, struct file_acl *filp);
//Pre: proc acl to operate on, proc object to remove
//Post: removes filp from proc acl proc

void expand_acls(void);
//Pre: process acl to operate on
//Post: handles override and inheritance for the passed proc acl

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
