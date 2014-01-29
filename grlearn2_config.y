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
extern void add_always_reduce(char *str);
extern void grlearn_configerror(const char *s);

#define grlearn2_configerror grlearn_configerror
#define grlearn2_configlex grlearn_configlex
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
		}
	|	INHERITLEARN FILENAME
		{
		}
	|	INHERITNOLEARN FILENAME
		{
		}
	|	DONTREDUCE FILENAME
		{
		}
	|	PROTECTED FILENAME
		{
		}
	|	READPROTECTED FILENAME
		{
		}
	|	HIGHREDUCE FILENAME
		{
		}
	|	ALWAYSREDUCE FILENAME
		{
			add_always_reduce($2);
		}
	|	HIGHPROTECTED FILENAME
		{
		}
	|	NOALLOWEDIPS
		{
		}
	|	SPLITROLES
		{
		}
	;
%%
