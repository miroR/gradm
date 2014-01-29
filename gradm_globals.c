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

#include "gradm.h"

struct glob_file *glob_files_head;
struct glob_file *glob_files_tail;
struct symlink *symlinks;
struct proc_acl *global_nested_subject_list;
struct deleted_file *deleted_files;
struct role_acl *current_role;
struct proc_acl *current_subject;
char *current_acl_file;

int is_24_kernel;

uid_t special_role_uid;

u_int32_t num_subjects;
u_int32_t num_roles;
u_int32_t num_objects;
u_int32_t num_pointers;
u_int32_t num_domain_children;

char *current_learn_rolename;
char *current_learn_subject;
u_int16_t current_learn_rolemode;

char ** dont_reduce_dirs;
char ** always_reduce_dirs;
char ** protected_paths;
char ** read_protected_paths;
char ** high_reduce_dirs;
char ** high_protected_paths;
u_int32_t grlearn_options;

char *output_log;

char *learn_log_buffer;
