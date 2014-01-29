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
extern int fulllearn_pass1lex(void);

extern struct gr_learn_group_node *the_role_list;
%}

%union {
	char * string;
	unsigned long num;
}

%token <num> NUM IPADDR FILENAME ROLENAME USER GROUP
%type <num> filename id_type

%%

learn_logs:	learn_log
	|	learn_logs learn_log
	;

filename:	/*empty*/	{ $$ = 1; }
	|	FILENAME	{ $$ = 1; }
	;

id_type:	USER
	|	GROUP
	;

learn_log:
		error
	|	ROLENAME ':' NUM ':' NUM ':' NUM ':' filename ':' filename ':' NUM ':' NUM ':' filename ':' NUM ':' IPADDR
		{
			const char *user;
			const char *group;
			uid_t uid;
			gid_t gid;

			uid = $5;
			gid = $7;

			user = gr_get_user_name(uid);
			group = gr_get_group_name(gid);

			if (user && group)
				insert_user(&the_role_list, user, group, uid, gid);
		}		
	|	ROLENAME ':' NUM ':' NUM ':' NUM ':' filename ':' filename ':' IPADDR ':' NUM ':' NUM ':' NUM ':' NUM ':' IPADDR
		{
			const char *user;
			const char *group;
			uid_t uid;
			gid_t gid;

			uid = $5;
			gid = $7;

			user = gr_get_user_name(uid);
			group = gr_get_group_name(gid);

			if (user && group)
				insert_user(&the_role_list, user, group, uid, gid);
		}
	|	ROLENAME ':' NUM ':' NUM ':' NUM ':' filename ':' filename ':' id_type ':' NUM ':' NUM ':' NUM ':' IPADDR
		{
			const char *user;
			const char *group;
			uid_t uid;
			gid_t gid;

			uid = $5;
			gid = $7;

			user = gr_get_user_name(uid);
			group = gr_get_group_name(gid);

			if (user && group)
				insert_user(&the_role_list, user, group, uid, gid);
		}
	;
%%
