/*
 * Copyright (C) 2002-2014 Bradley Spengler, Open Source Security, Inc.
 *        http://www.grsecurity.net spender@grsecurity.net
 *
 * This file is part of gradm.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

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
#include <dirent.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pwd.h>
#include <grp.h>
#include <fnmatch.h>
#include <elf.h>
#include <limits.h>
#include <assert.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <asm/param.h>
#include <asm/ioctls.h>

#define SIZE(x) (sizeof(x) / sizeof(x[0]))

#define failure(x) do { \
	fprintf(stderr, x ": %s\n\n", strerror(errno)); \
	exit(EXIT_FAILURE);\
  	} while(0)

#define for_each_role(x, y) \
	for(x = y; x; x = (x)->prev)

#define for_each_subject(x, y) \
	for(x = (struct proc_acl *)(y)->hash->first; x; x = (x)->prev)

#define for_each_nested_subject(x) \
	for (x = global_nested_subject_list; x; x = (x)->next)

#define for_each_include(x) \
	for(x = includes; x; x = (x)->prev)

#define for_each_file_object(x, y) \
	for(x = (struct file_acl *)(y)->hash->first; x; x = (x)->prev)

#define for_each_allowed_ip(x, y) \
	for(x = y; x; x = (x)->prev)

#define for_each_transition(x, y) \
	for(x = y; x; x = (x)->prev)

#define for_each_globbed(x, y) \
	for(x = (y)->globbed; x; x = (x)->next)

#define for_each_leaf(x, y) \
	for (x = (y)->leaves; x; x = (x)->next)

#define for_each_list_entry(x, y) \
	for (x = (y); x; x = (x)->next)

#define for_each_removable_list_entry(x, y) \
	for (x = (y); x;)

#define for_each_removable_list_entry_end(x) 	\
		if (removed)			\
			removed = 0;		\
		else				\
			x = (x)->next;

#define for_each_parent_entry(x, y) \
	for (x = (y); x; x = (x)->parent)

#define establish_new_head(list, head, tmp)	\
	do {					\
		(tmp) = (list);			\
		(head)->next = (tmp);		\
		if ((tmp))			\
			(tmp)->prev = (head);	\
		(list) = (head);		\
	} while (0);

#define for_each_variable(x, y) \
	for (x = (y); x; x = (x)->next)

#define get_list_head(x)			\
	({					\
		typeof (x) _x = (x);		\
		while (_x->prev)		\
			_x = _x->prev;		\
		_x;				\
	})

#define MAJOR_26(dev)     ((unsigned int) ((dev)>>20))
#define MINOR_26(dev)     ((unsigned int) ((dev) & ((1U << 20) - 1)))
#define MKDEV_26(ma,mi)   ((mi & 0xff) | (ma << 8) | ((mi & ~0xff) << 12))
#define MAJOR_24(dev)	((dev)>>8)
#define MINOR_24(dev)	((dev) & 0xff)
#define MKDEV_24(ma,mi)	((ma)<<8 | (mi))

#include "gradm_defs.h"
#include "gradm_func.h"

#endif
