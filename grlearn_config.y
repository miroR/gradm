%{
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
extern int grlearn_configlex(void);
%}

%union {
	char * string;
	unsigned long num;
}

%token <string> FILENAME NOLEARN INHERITLEARN INHERITNOLEARN DONTREDUCE 
%token <string> PROTECTED HIGHPROTECTED HIGHREDUCE ALWAYSREDUCE NOALLOWEDIPS
%token <string> READPROTECTED SPLITROLES
%token <num> NUM

%%

learn_config_file:	learn_config
		|	learn_config_file learn_config
		;

learn_config:
		NOLEARN FILENAME
		{
			if (current_role != NULL) {
				add_proc_subject_acl(current_role, $2, proc_subject_mode_conv("o"), 0);
				add_proc_object_acl(current_subject, "/", proc_object_mode_conv("rwxcdm"), GR_FEXIST);
			}
		}
	|	INHERITLEARN FILENAME
		{
			struct ip_acl ip;
			if (current_role != NULL) {
				add_proc_subject_acl(current_role, $2, proc_subject_mode_conv("oi"), 0);
				add_proc_object_acl(current_subject, "/", proc_object_mode_conv("h"), GR_FEXIST);
				add_cap_acl(current_subject, "-CAP_ALL", NULL);

				memset(&ip, 0, sizeof (ip));
				add_ip_acl(current_subject, GR_IP_CONNECT, &ip);
				add_ip_acl(current_subject, GR_IP_BIND, &ip);
			}
		}
	|	INHERITNOLEARN FILENAME
		{
			if (current_role != NULL) {
				add_proc_subject_acl(current_role, $2, proc_subject_mode_conv("o"), 0);
				add_proc_object_acl(current_subject, "/", proc_object_mode_conv("rwxcdmi"), GR_FEXIST);
			}
		}
	|	DONTREDUCE FILENAME
		{
			add_to_string_array(&dont_reduce_dirs, $2);
		}
	|	PROTECTED FILENAME
		{
			add_to_string_array(&protected_paths, $2);
		}
	|	READPROTECTED FILENAME
		{
			add_to_string_array(&read_protected_paths, $2);
		}
	|	HIGHREDUCE FILENAME
		{
			add_to_string_array(&high_reduce_dirs, $2);
		}
	|	ALWAYSREDUCE FILENAME
		{
			add_to_string_array(&always_reduce_dirs, $2);
		}
	|	HIGHPROTECTED FILENAME
		{
			add_to_string_array(&high_protected_paths, $2);
		}
	|	NOALLOWEDIPS
		{
			add_grlearn_option(GR_DONT_LEARN_ALLOWED_IPS);
		}
	|	SPLITROLES
		{
			add_grlearn_option(GR_SPLIT_ROLES);
		}
	;
%%
