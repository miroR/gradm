#ifndef GRSEC_DIR
#define GRSEC_DIR		"/etc/grsec"
#endif
#define GRLEARN_PATH		"/sbin/grlearn"
#define GRDEV_PATH		"/dev/grsec"
#define GR_ACL_PATH 		GRSEC_DIR "/acl"
#define GR_PW_PATH 		GRSEC_DIR "/pw"

#define GR_VERSION		"2.0-rc5"

#define GR_PWONLY		0
#define GR_PWANDSUM		1

#define GR_PW_LEN		128
#define GR_SALT_SIZE		16
#define GR_SHA_SUM_SIZE		32

#define GR_SPROLE_LEN		64

#define GR_FEXIST		0x1
#define GR_FFAKE		0x2
#define GR_FLEARN		0x4
#define GR_SYMLINK		0x8

#define CHK_FILE		0
#define CHK_CAP			1

#undef PATH_MAX
#define PATH_MAX 		4096
#define MAX_LINE_LEN 		5000

#define MAX_INCLUDE_DEPTH	10
#define MAX_NEST_DEPTH		8

#define GR_NLIMITS	(RLIM_NLIMITS + 1)

enum {
	GRADM_DISABLE = 0,
	GRADM_ENABLE = 1,
	GRADM_SPROLE = 2,
	GRADM_RELOAD = 3,
	GRADM_MODSEGV = 4,
	GRADM_STATUS = 5,
	GRADM_UNSPROLE = 6
};

enum {
	GR_IP_BIND = 0x01,
	GR_IP_CONNECT = 0x02,
};

enum {
	GR_READ 	= 0x00000001,
	GR_APPEND 	= 0x00000002,
	GR_WRITE 	= 0x00000004,
	GR_EXEC 	= 0x00000008,
	GR_FIND 	= 0x00000010,
	GR_INHERIT 	= 0x00000040,
	GR_PTRACERD 	= 0x00000100,
	GR_SETID 	= 0x00000200,
	GR_CREATE 	= 0x00000400,
	GR_DELETE 	= 0x00000800,
	GR_AUDIT_READ 	= 0x00001000,
	GR_AUDIT_APPEND = 0x00002000,
	GR_AUDIT_WRITE 	= 0x00004000,
	GR_AUDIT_EXEC 	= 0x00008000,
	GR_AUDIT_FIND 	= 0x00010000,
	GR_AUDIT_INHERIT= 0x00020000,
	GR_AUDIT_SETID 	= 0x00040000,
	GR_AUDIT_CREATE = 0x00080000,
	GR_AUDIT_DELETE = 0x00100000,
	GR_SUPPRESS 	= 0x00200000
};

enum {
	GR_ROLE_USER = 0x0001,
	GR_ROLE_GROUP = 0x0002,
	GR_ROLE_DEFAULT = 0x0004,
	GR_ROLE_SPECIAL = 0x0008,
	GR_ROLE_AUTH = 0x0010,
	GR_ROLE_NOPW = 0x0020,
	GR_ROLE_GOD = 0x0040,
	GR_ROLE_LEARN = 0x0080,
	GR_ROLE_TPE = 0x0100
};

enum {
	GR_DELETED = 0x00000080
};

enum {
	GR_KILL 	= 0x00000001,
	GR_VIEW 	= 0x00000002,
	GR_PROTECTED 	= 0x00000100,
	GR_LEARN 	= 0x00000200,
	GR_IGNORE 	= 0x00000400,
	GR_OVERRIDE 	= 0x00000800,
	GR_PAXPAGE 	= 0x00001000,
	GR_PAXSEGM 	= 0x00002000,
	GR_PAXGCC 	= 0x00004000,
	GR_PAXRANDMMAP 	= 0x00008000,
	GR_PAXRANDEXEC 	= 0x00010000,
	GR_PAXMPROTECT 	= 0x00020000,
	GR_PROTSHM 	= 0x00040000,
	GR_KILLPROC 	= 0x00080000,
	GR_KILLIPPROC 	= 0x00100000,
	GR_NOTROJAN 	= 0x00200000,
	GR_PROTPROCFD 	= 0x00400000,
	GR_PROCACCT 	= 0x00800000,
	GR_NOPTRACE	= 0x01000000,
	GR_RELAXPTRACE  = 0x02000000,
	GR_NESTED	= 0x04000000
};

/* internal use only.  not to be modified */

struct capability_set {
	char *cap_name;
	__u32 cap_val;
};

struct rlimconv {
	const char *name;
	unsigned short val;
};

struct chk_perm {
	unsigned short type;
	__u32 w_modes;
	__u32 u_modes;
	__u32 w_caps;
	__u32 u_caps;
};

struct role_allowed_ip {
	__u32 addr;
	__u32 netmask;

	struct role_allowed_ip *prev;
	struct role_allowed_ip *next;
};

struct ip_acl {
	__u32 addr;
	__u32 netmask;
	__u16 low, high;
	__u8 mode;		// connect or bind
	__u32 type;		// stream, dgram, raw..etc
	__u32 proto[8];		// we have to support all 255 protocols

	struct ip_acl *prev;
	struct ip_acl *next;
};

struct file_acl {
	char *filename;
	ino_t inode;
	unsigned short dev;
	__u32 mode;

	struct proc_acl *nested;
	struct file_acl *globbed;

	struct file_acl *prev;
	struct file_acl *next;
};

struct var_object {
	char *filename;
	__u32 mode;

	struct var_object *prev;
	struct var_object *next;
};

struct role_transition {
	char *rolename;

	struct role_transition *prev;
	struct role_transition *next;
};

struct role_acl {
	char *rolename;
	uid_t uidgid;
	__u16 roletype;

	__u16 auth_attempts;
	unsigned long expires;

	struct proc_acl *root_label;
	struct gr_hash_struct *hash;

	struct role_acl *prev;
	struct role_acl *next;

	struct role_transition *transitions;
	struct role_allowed_ip *allowed_ips;

	struct proc_acl **subj_hash;
	__u32 subj_hash_size;
};

struct proc_acl {
	char *filename;
	ino_t inode;
	unsigned short dev;
	__u32 mode;
	__u32 cap_mask;
	__u32 cap_drop;

	struct rlimit res[GR_NLIMITS];
	__u16 resmask;

	__u32 ip_proto[8];
	__u32 ip_type;
	struct ip_acl **ips;
	__u32 ip_num;

	__u32 crashes;
	unsigned long expires;

	struct proc_acl *parent_subject;
	struct gr_hash_struct *hash;
	struct ip_acl *ip_object;
	struct proc_acl *prev;
	struct proc_acl *next;

	struct file_acl **obj_hash;
	__u32 obj_hash_size;
};

struct gr_learn_ip_node {
	__u8 ip_node;
	__u16 **ports;
	__u32 ip_proto[8];
	__u32 ip_type;
	unsigned char root_node:1;
	unsigned char all_low_ports:1;
	unsigned char all_high_ports:1;
	struct gr_learn_ip_node *parent;
	struct gr_learn_ip_node **leaves;
};

struct gr_learn_role_entry {
	char *rolename;
	__u16 rolemode;
	unsigned int id;
	struct gr_learn_file_tmp_node **tmp_subject_list;
	struct gr_learn_file_node *subject_list;
	struct gr_learn_ip_node *allowed_ips;
};	

struct gr_learn_group_node {
	char *rolename;
	gid_t gid;
	struct gr_learn_user_node **users;
	struct gr_learn_file_tmp_node ** tmp_subject_list;
	struct gr_learn_file_node *subject_list;
	struct gr_learn_ip_node *allowed_ips;
};

struct gr_learn_file_tmp_node {
	char *filename;
	__u32 mode;
};

struct gr_learn_user_node {
	char *rolename;
	uid_t uid;
	struct gr_learn_group_node *group;
	struct gr_learn_file_tmp_node ** tmp_subject_list;
	struct gr_learn_file_node *subject_list;
	struct gr_learn_ip_node *allowed_ips;
};

struct gr_learn_subject_node {
	__u32 cap_raise;
	struct rlimit res[GR_NLIMITS];
	__u16 resmask;
};

struct gr_learn_file_node {
	char *filename;
	__u32 mode;
	unsigned char dont_display:1;
	struct gr_learn_file_node **leaves;
	struct gr_learn_file_node *parent;
	struct gr_learn_file_tmp_node ** tmp_object_list;
	struct gr_learn_file_node *object_list;
	struct gr_learn_ip_node *connect_list;
	struct gr_learn_ip_node *bind_list;
	struct gr_learn_subject_node *subject;
};

struct gr_pw_entry {
	unsigned char rolename[GR_SPROLE_LEN];
	unsigned char passwd[GR_PW_LEN];
	unsigned char sum[GR_SHA_SUM_SIZE];
	unsigned char salt[GR_SALT_SIZE];
	unsigned short segv_dev;
	ino_t segv_inode;
	uid_t segv_uid;
	__u16 mode;
};

/* We use this to keep track of deleted files, since each subject needs
   to agree on an inode/dev
*/

struct deleted_file {
	char *filename;
	ino_t ino;
	struct deleted_file *next;
} *deleted_files;

unsigned long lineno;

struct role_acl *current_role;
struct proc_acl *current_subject;

char *current_acl_file;

enum {
	GR_HASH_SUBJECT,
	GR_HASH_OBJECT,
};

struct gr_hash_struct {
	void **table;
	void **nametable;
	void *first;
	__u32 table_size;
	__u32 used_size;
	int type;
};

struct user_acl_role_db {
	struct role_acl **r_table;
	__u32 r_entries;	/* Number of entries in table */
	__u32 s_entries;	/* total number of subject acls */
	__u32 i_entries;	/* total number of ip acls */
	__u32 o_entries;	/* Total number of object acls */
	__u32 g_entries;	/* total number of globbed objects */
	__u32 a_entries;	/* total number of allowed role ips */
	__u32 t_entries;	/* total number of transitions */
};

struct sprole_pw {
	unsigned char *rolename;
	unsigned char salt[GR_SALT_SIZE];
	unsigned char sum[GR_SHA_SUM_SIZE];
};

struct gr_arg {
	struct user_acl_role_db role_db;
	unsigned char pw[GR_PW_LEN];
	unsigned char salt[GR_SALT_SIZE];
	unsigned char sum[GR_SHA_SUM_SIZE];
	unsigned char sp_role[GR_SPROLE_LEN];
	struct sprole_pw *sprole_pws;
	__u16 num_sprole_pws;
	unsigned short segv_dev;
	ino_t segv_inode;
	uid_t segv_uid;
	__u16 mode;
};

struct capability_set capability_list[30];
struct rlimconv rlim_table[12];

uid_t special_role_uid;
