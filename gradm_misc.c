#include "gradm.h"

FILE * open_acl_file(const char * filename)
{
	FILE *aclfile;

	if((aclfile = fopen(filename, "r")) == NULL) {
		fprintf(stderr, "Unable to open %s for reading.\n", filename);
		failure("fopen");
	}
	
	return aclfile;
}

void transmit_to_kernel(void * buf, unsigned long len)
{
	int fd;

        if((fd = open(GR_SYSCTL_PATH, O_WRONLY)) < 0) {
                fprintf(stderr, "Could not open %s\n", GR_SYSCTL_PATH);
		failure("open");
        }
                 
        if(write(fd, buf, len) != len) {
                fprintf(stderr, "Error writing to %s\n", GR_SYSCTL_PATH);
		failure("write");
        }

	close(fd);

	return;
}

void init_variables(void)
{
	extern struct ip_acl ip;
        lineno = 1;
                 
	current_acl_file = NULL;
	includes = NULL;
	current_role = NULL;
	current_subject = NULL;

	memset(&ip, 0, sizeof(ip));

	return;
}

void change_current_acl_file(const char * filename)
{
	char * p;

	if((p = (char *) calloc(strlen(filename) + 1, sizeof(char))) == NULL)
		failure("calloc");
		
	strncpy(p, filename, strlen(filename));

	current_acl_file = p;
	
	return;
}

int parent_dir(const char * filename, char * parent_dirent[])
{
	int i;

	if((strlen(*parent_dirent) <= 1) || (strlen(filename) <= 1))
		return 0;

	for(i=strlen(*parent_dirent)-1;i>=0;i--) {
		if(i)
			(*parent_dirent)[i] = '\0';
		if(filename[i] == '/')
			return 1;
	}

	return 0;
}

void syslog_lookup_log(char ** learn_log)
{
	FILE * syslog_conf;
	char * buf;
	char * p = NULL;
	char * p2;

	buf = calloc(MAX_LINE_LEN + 1, sizeof(char));

	if(!buf)
		failure("calloc");

	syslog_conf = fopen(SYSLOG_CONF, "r");

	if(!syslog_conf) {
		fprintf(stderr, "Unable to open %s for reading.\n"
			"Error: %s\n", SYSLOG_CONF, strerror(errno));
		exit(EXIT_FAILURE);
	}

	while(fgets(buf, MAX_LINE_LEN, syslog_conf)) {
		p = strchr(buf, '#');
		if(p) *p = '\0';
		if(strstr(buf, "kern.*") || strstr(buf, "kern.=info")
		   || strstr(buf, "kern.debug") || strstr(buf, "*.debug")
		   || strstr(buf, "*.=info") || strstr(buf, "*.info")
		   || strstr(buf, "kern.info") || strstr(buf, "*.*")) {
			p = strchr(buf, '/');
			if(p) {
				if(!strncmp(p, "/dev", 4))
					continue;
				p2 = strchr(p, '\n');
				if(p2) *p2 = '\0';
				break;
			}
		}
	}

	if(!p) {
		fprintf(stderr, "Unable to find log to scan from %s.\n"
				"Please report this to dev@grsecurity.net "
				"and attach your %s file.\n", SYSLOG_CONF,
				SYSLOG_CONF);
		exit(EXIT_FAILURE);
	}

	*learn_log = strdup(p);

	if(!*learn_log)
		failure("strdup");

	free(buf);
	fclose(syslog_conf);
	return;
}
