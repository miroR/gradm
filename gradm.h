#ifndef GRADM_H
#define GRADM_H
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <fcntl.h>
#include <termios.h>
#include <sys/stat.h>
#include <asm/param.h>
#include <glob.h>
#include <dirent.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pwd.h>
#include <grp.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <asm/posix_types.h>
#include <linux/elf.h>
#include <linux/capability.h>

#include "gradm_defs.h"
#include "gradm_func.h"

#define failure(x) do { \
	fprintf(stderr, x ": %s\n\n", strerror(errno)); \
	exit(EXIT_FAILURE);\
  	} while(0)

#define for_each_role(x, y) \
	for(x = y; x; x = (x)->prev)

#define for_each_subject(x, y) \
	for(x = (y)->proc_subject; x; x = (x)->prev)

#define for_each_include(x) \
	for(x = includes; x; x = (x)->prev)

#define for_each_object(x, y) \
	for(x = y; x; x = (x)->prev)

#define for_each_allowed_ip(x, y) \
	for(x = y; x; x = (x)->prev)

#define for_each_transition(x, y) \
	for(x = y; x; x = (x)->prev)

#endif
