#ifndef GRSEC_DIR
#define GRSEC_DIR		"/etc/grsec"
#endif
#define GRLEARN_PATH		"/sbin/grlearn"
#define GRDEV_PATH		"/dev/grsec"
#define GR_POLICY_PATH 		GRSEC_DIR "/policy"
#define GR_PW_PATH 		GRSEC_DIR "/pw"
#define GR_LEARN_CONFIG_PATH	GRSEC_DIR "/learn_config"

#define GR_VERSION		"2.0.3"
#define GRADM_VERSION		0x203

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

#ifndef RLIMIT_LOCKS
#define RLIMIT_LOCKS 10
#endif
#define GR_NLIMITS	(RLIMIT_LOCKS + 2)

enum {
	GRADM_DISABLE 	= 0,
	GRADM_ENABLE 	= 1,
	GRADM_SPROLE 	= 2,
	GRADM_RELOAD 	= 3,
	GRADM_MODSEGV 	= 4,
	GRADM_STATUS 	= 5,
	GRADM_UNSPROLE 	= 6
};

enum {
	GR_IP_BIND 	= 0x01,
	GR_IP_CONNECT 	= 0x02,
};

enum {
	GR_ID_USER 	= 0x01,
	GR_ID_GROUP 	= 0x02,
};

enum {
	GR_ID_ALLOW	= 0x01,
	GR_ID_DENY	= 0x02,
};

enum {
	GR_READ 	= 0x00000001,
	GR_APPEND 	= 0x00000002,
	GR_WRITE 	= 0x00000004,
	GR_EXEC 	= 0x00000008,
	GR_FIND 	= 0x00000010,
	GR_INHERIT 	= 0x00000020,
	GR_SETID 	= 0x00000040,
	GR_CREATE 	= 0x00000080,
	GR_DELETE 	= 0x00000100,
	GR_AUDIT_READ 	= 0x00000200,
	GR_AUDIT_APPEND = 0x00000400,
	GR_AUDIT_WRITE 	= 0x00000800,
	GR_AUDIT_EXEC 	= 0x00001000,
	GR_AUDIT_FIND 	= 0x00002000,
	GR_AUDIT_INHERIT= 0x00004000,
	GR_AUDIT_SETID 	= 0x00008000,
	GR_AUDIT_CREATE = 0x00010000,
	GR_AUDIT_DELETE = 0x00020000,
	GR_PTRACERD 	= 0x00040000,
	GR_NOPTRACE	= 0x00080000,
	GR_SUPPRESS 	= 0x00100000
};

enum {
	GR_ROLE_USER 	= 0x0001,
	GR_ROLE_GROUP 	= 0x0002,
	GR_ROLE_DEFAULT = 0x0004,
	GR_ROLE_SPECIAL = 0x0008,
	GR_ROLE_AUTH 	= 0x0010,
	GR_ROLE_NOPW 	= 0x0020,
	GR_ROLE_GOD 	= 0x0040,
	GR_ROLE_LEARN 	= 0x0080,
	GR_ROLE_TPE 	= 0x0100,
	GR_ROLE_DOMAIN 	= 0x0200
};

enum {
	GR_DELETED = 0x00400000
};

enum {
	GR_KILL 	= 0x00000001,
	GR_VIEW 	= 0x00000002,
	GR_PROTECTED 	= 0x00000004,
	GR_LEARN 	= 0x00000008,
	GR_IGNORE 	= 0x00000010,
	GR_OVERRIDE 	= 0x00000020,
	GR_PAXPAGE 	= 0x00000040,
	GR_PAXSEGM 	= 0x00000080,
	GR_PAXGCC 	= 0x00000100,
	GR_PAXRANDMMAP 	= 0x00000200,
	GR_PAXRANDEXEC 	= 0x00000400,
	GR_PAXMPROTECT 	= 0x00000800,
	GR_PROTSHM 	= 0x00001000,
	GR_KILLPROC 	= 0x00002000,
	GR_KILLIPPROC 	= 0x00004000,
	GR_NOTROJAN 	= 0x00008000,
	GR_PROTPROCFD 	= 0x00010000,
	GR_PROCACCT 	= 0x00020000,
	GR_RELAXPTRACE  = 0x00040000,
	GR_NESTED	= 0x00080000,
	GR_INHERITLEARN = 0x00100000
};

/* internal use only.  not to be modified */

struct capability_set {
	char *cap_name;
	u_int32_t cap_val;
};

struct rlimconv {
	const char *name;
	unsigned short val;
};

struct chk_perm {
	unsigned short type;
	u_int32_t w_modes;
	u_int32_t u_modes;
	u_int32_t w_caps;
	u_int32_t u_caps;
};

struct role_allowed_ip {
	u_int32_t addr;
	u_int32_t netmask;

	struct role_allowed_ip *prev;
	struct role_allowed_ip *next;
};

struct ip_acl {
	u_int32_t addr;
	u_int32_t netmask;
	u_int16_t low, high;
	u_int8_t mode;		// connect or bind
	u_int32_t type;		// stream, dgram, raw..etc
	u_int32_t proto[8];		// we have to support all 255 protocols

	struct ip_acl *prev;
	struct ip_acl *next;
};

struct file_acl {
	char *filename;
	ino_t inode;
	gr_dev_t dev;
	u_int32_t mode;

	struct proc_acl *nested;
	struct file_acl *globbed;

	struct file_acl *prev;
	struct file_acl *next;
};

struct var_object {
	char *filename;
	u_int32_t mode;

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
	u_int16_t roletype;

	u_int16_t auth_attempts;
	unsigned long expires;

	struct proc_acl *root_label;
	struct gr_hash_struct *hash;

	struct role_acl *prev;
	struct role_acl *next;

	struct role_transition *transitions;
	struct role_allowed_ip *allowed_ips;
	uid_t *domain_children;
	u_int16_t domain_child_num;

	struct proc_acl **subj_hash;
	u_int32_t subj_hash_size;
};

struct proc_acl {
	char *filename;
	ino_t inode;
	gr_dev_t dev;
	u_int32_t mode;
	u_int32_t cap_mask;
	u_int32_t cap_drop;

	struct rlimit res[GR_NLIMITS];
	u_int16_t resmask;

	u_int8_t user_trans_type;
	u_int8_t group_trans_type;
	uid_t *user_transitions;
	gid_t *group_transitions;
	u_int16_t user_trans_num;
	u_int16_t group_trans_num;

	u_int32_t ip_proto[8];
	u_int32_t ip_type;
	struct ip_acl **ips;
	u_int32_t ip_num;

	u_int32_t crashes;
	unsigned long expires;

	struct proc_acl *parent_subject;
	struct gr_hash_struct *hash;
	struct proc_acl *prev;
	struct proc_acl *next;

	struct file_acl **obj_hash;
	u_int32_t obj_hash_size;
};

struct gr_learn_ip_node {
	u_int8_t ip_node;
	u_int16_t **ports;
	u_int32_t ip_proto[8];
	u_int32_t ip_type;
	unsigned char root_node:1;
	unsigned char all_low_ports:1;
	unsigned char all_high_ports:1;
	struct gr_learn_ip_node *parent;
	struct gr_learn_ip_node **leaves;
};

struct gr_learn_role_entry {
	char *rolename;
	u_int16_t rolemode;
	unsigned int id;
	struct gr_hash_struct *hash;
	struct gr_learn_file_node *subject_list;
	struct gr_learn_ip_node *allowed_ips;
};	

struct gr_learn_group_node {
	char *rolename;
	gid_t gid;
	struct gr_learn_user_node **users;
	struct gr_hash_struct *hash;
	struct gr_learn_file_node *subject_list;
	struct gr_learn_ip_node *allowed_ips;
};

struct gr_learn_file_tmp_node {
	char *filename;
	u_int32_t mode;
};

struct gr_learn_user_node {
	char *rolename;
	uid_t uid;
	struct gr_learn_group_node *group;
	struct gr_hash_struct *hash;
	struct gr_learn_file_node *subject_list;
	struct gr_learn_ip_node *allowed_ips;
};

struct gr_learn_subject_node {
	u_int32_t cap_raise;
	struct rlimit res[GR_NLIMITS];
	u_int16_t resmask;
};

struct gr_learn_file_node {
	char *filename;
	u_int32_t mode;
	struct gr_learn_file_node **leaves;
	struct gr_learn_file_node *parent;
	struct gr_hash_struct *hash;
	struct gr_learn_file_node *object_list;
	struct gr_learn_ip_node *connect_list;
	struct gr_learn_ip_node *bind_list;
	struct gr_learn_subject_node *subject;
	unsigned char dont_display:1;
};

struct gr_pw_entry {
	unsigned char rolename[GR_SPROLE_LEN];
	unsigned char passwd[GR_PW_LEN];
	unsigned char sum[GR_SHA_SUM_SIZE];
	unsigned char salt[GR_SALT_SIZE];
	gr_dev_t segv_dev;
	ino_t segv_inode;
	uid_t segv_uid;
	u_int16_t mode;
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
	GR_HASH_FILENAME
};

struct gr_hash_struct {
	void **table;
	void **nametable;
	void *first;
	u_int32_t table_size;
	u_int32_t used_size;
	int type;
};

struct user_acl_role_db {
	struct role_acl **r_table;
	u_int32_t num_pointers;		/* Number of allocations to track */
	u_int32_t num_roles;		/* Number of roles */
	u_int32_t num_domain_children;	/* Number of domain children */
	u_int32_t num_subjects;		/* Number of subjects */
	u_int32_t num_objects; 		/* Number of objects */
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
	gr_dev_t segv_dev;
	ino_t segv_inode;
	uid_t segv_uid;
	u_int16_t num_sprole_pws;
	u_int16_t mode;
};

struct gr_arg_wrapper {
	struct gr_arg *arg;
	u_int32_t version;
	u_int32_t size;
};

struct capability_set capability_list[30];
struct rlimconv rlim_table[12];

uid_t special_role_uid;

u_int32_t num_subjects;
u_int32_t num_roles;
u_int32_t num_objects;
u_int32_t num_pointers;
u_int32_t num_domain_children;

char *current_learn_rolename;
char *current_learn_subject;
u_int16_t current_learn_rolemode;
