#define GR_SYSCTL_PATH 		"/proc/sys/kernel/grsecurity/acl"

#define GRSEC_DIR		"/etc/grsec"
#define GR_ACL_PATH 		GRSEC_DIR "/acl"
#define GR_PW_PATH 		GRSEC_DIR "/pw"

#define SYSLOG_CONF		"/etc/syslog.conf"

#define GR_VERSION		"2.0"

#define GR_PWONLY		0
#define GR_PWANDSUM		1

#define GR_PW_LEN		128
#define GR_SALT_SIZE		16
#define GR_SHA_SUM_SIZE		32

#define GR_SPROLE_LEN		64

#define GR_FEXIST		0x1
#define GR_FFAKE		0x2
#define GR_FLEARN		0x4
#define GR_GLOB			0x8

#define CHK_FILE		0
#define CHK_CAP			1

#undef PATH_MAX
#define PATH_MAX 		4096
#define MAX_LINE_LEN 		5000

#define GR_LEARN_THRESH		4

#define GR_NLIMITS	(RLIM_NLIMITS + 1)

enum {
	GRADM_DISABLE	= 0,
	GRADM_ENABLE	= 1,
	GRADM_SPROLE	= 2,
	GRADM_RELOAD	= 3,
	GRADM_MODSEGV	= 4
};

enum {
	GR_IP_BIND= 0x01,
	GR_IP_CONNECT = 0x02,
};

enum {
	GR_READ		 = 0x00000001,
	GR_APPEND	 = 0x00000002,
	GR_WRITE	 = 0x00000004,
	GR_EXEC		 = 0x00000008,
	GR_FIND		 = 0x00000010,
	GR_INHERIT	 = 0x00000040,
	GR_PTRACERD	 = 0x00000100,
	GR_AUDIT_READ	 = 0x00000200,
	GR_AUDIT_APPEND  = 0x00000400,
	GR_AUDIT_WRITE   = 0x00001000,
	GR_AUDIT_EXEC    = 0x00002000,
	GR_AUDIT_FIND    = 0x00004000,
	GR_AUDIT_INHERIT = 0x00008000,
	GR_SUPPRESS	 = 0x00010000
};

enum {
	GR_ROLE_USER	= 0x01,
	GR_ROLE_GROUP	= 0x02,
	GR_ROLE_DEFAULT = 0x04,
	GR_ROLE_SPECIAL = 0x08,
	GR_ROLE_NOPW	= 0x10,
	GR_ROLE_GOD	= 0x20
};

enum {
	GR_DELETED	= 0x00000080
};

enum {
	GR_KILL		= 0x00000001,
	GR_VIEW		= 0x00000002,
	GR_PROTECTED	= 0x00000100,
	GR_LEARN	= 0x00000200,
	GR_IGNORE	= 0x00000400,
	GR_OVERRIDE	= 0x00000800,
	GR_PAXPAGE	= 0x00001000,
	GR_PAXSEGM	= 0x00002000,
	GR_PAXGCC	= 0x00004000,
	GR_PAXRANDMMAP	= 0x00008000,
	GR_PAXRANDEXEC	= 0x00010000,
	GR_PAXMPROTECT	= 0x00020000,
	GR_PROTSHM	= 0x00040000,
	GR_KILLPROC	= 0x00080000,
	GR_KILLIPPROC	= 0x00100000,
	GR_NOTROJAN	= 0x00200000,
	GR_PROTPROCFD	= 0x00400000,
	GR_PROCACCT	= 0x00800000
};

/* internal use only.  not to be modified */

struct capability_set {
	char *cap_name;
	__u32 cap_val;
};

struct rlimconv {
	const char * name;
	unsigned short val;
};

struct learn_info {
	char * rolename;
	__u8 roletype;
	char *subjname;
	char * obj_name;
	__u32 res_cur, res_max;
	__u32 mode;
};

struct ip_learn_info {
	char *rolename;
	__u8 roletype;
	char *subjname;
	__u32 addr;
	__u16 port;
	__u16 sock;
	__u16 proto;
	__u16 mode;
};

struct chk_perm {
	unsigned short type;
	__u32 w_modes;
	__u32 u_modes;
	__u32 w_caps;
	__u32 u_caps;
};


/************************************************************************\
|  none of these fields are to be modified directly.			 |
|  these structures only appear inside process acls.  They are not 	 |
|  permitted in the grammar of the configuration files to be outside of a| 
|  process acl.								 |
\************************************************************************/

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
	__u8 mode; // connect or bind
	__u32 type; // stream, dgram, raw..etc
	__u32 proto[8];  // we have to support all 255 protocols

	struct ip_acl * prev;
	struct ip_acl * next;
};

struct file_acl {
        char * filename;
	ino_t inode;
	unsigned short dev;
        __u32 mode;

	struct file_acl *prev;
        struct file_acl *next;
};

/************************************************************************\
|  none of these fields are to be modified directly.  modes, 		 |
|  capabilities, and filenames are verified before set.  proc_subject	 |
|  is filled out after all the proc_objects are collected for the current|
|  process acl								 |
\************************************************************************/
  
struct role_acl {
	char * rolename;
	uid_t uidgid;
	__u8 roletype;

	__u16 auth_attempts;
	unsigned long expires;

	struct proc_acl *root_label;
	struct proc_acl *proc_subject;

	struct role_acl *prev;
        struct role_acl *next;

	struct role_allowed_ip *allowed_ips;

	struct proc_acl **subj_hash;
	__u32 subj_hash_size;
};	

struct proc_acl {
        char * filename;
	ino_t inode;
	unsigned short dev;
        __u32 mode;
        __u32 cap_raise;
        __u32 cap_drop;

	struct rlimit res[GR_NLIMITS];
	__u16 resmask;

	__u32 ip_proto[8];
	__u32 ip_type;
	struct ip_acl ** ips;
	__u32 ip_num;

	__u32 crashes;
	unsigned long expires;

        struct file_acl *proc_object;
	struct ip_acl *ip_object;
	struct proc_acl *prev;
        struct proc_acl *next;

	struct file_acl **obj_hash;
	__u32 obj_hash_size;
};

/************************************************************************\
|  32768 permutations of each password. a dictionary attack of		 | 
|  1,000,000 passwords would require storage space of 32768 * 		 |
|  1000000 * (32 + 16) = 1.6 Terabytes					 |
|									 |
|  mode stores the operation we want to perform with the acl system.	 |
|  not all modes operate with the kernel.  Mode that initializes the 	 |
|  acl system and reads acls is enable.		 			 |
|  disable, and admin also interact with the kernel.		         |
\************************************************************************/

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

/************************************************************************\
|  used for keeping track of the current line number of the file we're   |
|  reading.  initialized to 1 before every new acl file is read		 |
\************************************************************************/

unsigned long lineno;

struct role_acl *current_role;
struct proc_acl *current_subject;

/************************************************************************\
|  used for the linked list of included files in acl configs.  no 	 |
|  structures of the linked list should be modified while in use, since	 |
|  it is used for duplicate checking.  This explains the somewhat	 |
|  complex code in gradm_parse.c in parse_acls()			 |
|  includes->next should never exist.  includes points to the last	 |
|  added include file.  The rest can be accessed through includes->prev  |
\************************************************************************/

struct include_line *includes;

/************************************************************************\
|  used to hold the name of the current acl file being read.  This	 |
|  pointer should not be modified directly.  Rather, 			 |
|  change_current_acl_file() should be used to change it, since it 	 |
|  auto-frees the current pointer.  This mainly has use to make error 	 |
|  logs more informative						 |
\************************************************************************/

char * current_acl_file;


/************************************************************************\
|  basically a dummy pointer.  its use is to set "magic" values to the   |
|  left member of the include_line structure.  We need this because while| 
|  we're operating on the current state of the includes linked list, by  |
|  parsing the included files, more included files may show up.		 |
|  Therefore we need some way to make sure that we don't re-parse a file |
|  we've already parsed (this would generated a duplicate error) and we  |
|  can't modify the important contents of the linked list.		 |
\************************************************************************/

unsigned int includeno;


struct user_acl_role_db {
	struct role_acl ** r_table;
	__u32 r_entries; /* Number of entries in table */
	__u32 s_entries; /* total number of subject acls */
	__u32 i_entries; /* total number of ip acls */
	__u32 o_entries; /* Total number of object acls */
	__u32 a_entries; /* total number of allowed role ips */
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

struct learn_info ** learn_db;
struct ip_learn_info ** ip_learn_db;
unsigned long learn_num;
unsigned long ip_learn_num;

struct capability_set capability_list[30];
struct rlimconv rlim_table[12];

uid_t special_role_uid;
