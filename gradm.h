#ifndef GRADM_H
#define GRADM_H
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <getopt.h>
#include <sched.h>
#include <fcntl.h>
#include <termios.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/poll.h>
#include <asm/param.h>
#include <asm/ioctls.h>
#include <dirent.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pwd.h>
#include <grp.h>
#include <fnmatch.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <asm/posix_types.h>
#include <linux/elf.h>
#include <linux/capability.h>
#include <linux/limits.h>
#include <linux/threads.h>
#include <linux/version.h>

#include "gradm_defs.h"
#include "gradm_func.h"

#define failure(x) do { \
	fprintf(stderr, x ": %s\n\n", strerror(errno)); \
	exit(EXIT_FAILURE);\
  	} while(0)

#define for_each_role(x, y) \
	for(x = y; x; x = (x)->prev)

#define for_each_subject(x, y) \
	for(x = (y)->hash->first; x; x = (x)->prev)

#define for_each_include(x) \
	for(x = includes; x; x = (x)->prev)

#define for_each_object(x, y) \
	for(x = (y)->hash->first; x; x = (x)->prev)

#define for_each_allowed_ip(x, y) \
	for(x = y; x; x = (x)->prev)

#define for_each_transition(x, y) \
	for(x = y; x; x = (x)->prev)

#define for_each_globbed(x, y) \
	for(x = (y)->globbed; x; x = (x)->next)


KERNEL_VERSION(a,b,c)

#if KERNEL_VERSION(2,6,0) < KERNEL_VERSION_CODE
typedef gr_dev_t __u32;
#undef MAJOR
#undef MINOR
#undef MKDEV
#define MAJOR(dev)     ((unsigned int) ((dev)>>20))
#define MINOR(dev)     ((unsigned int) ((dev) & ((1U << 20) - 1)))
#define MKDEV(ma,mi)   ((mi & 0xff) | (ma << 8) | ((mi & ~0xff) << 12))
#else
typedef gr_dev_t unsigned short
#define MAJOR(dev)	((dev)>>8)
#define MINOR(dev)	((dev) & 0xff)
#define MKDEV(ma,mi)	((ma)<<8 | (mi))
#endif

#endif
