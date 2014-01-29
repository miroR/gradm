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
#ifdef IS_GRLEARN
#include "grlearn2_config.tab.h"
#define grlearn_configlval grlearn2_configlval
#else
#include "grlearn_config.tab.h"
#endif

void grlearn_configerror(const char *s);
int grlearn_configwrap(void);

%}

NUM [0-9]+
FILENAME [/][^\t\n]*

%option nounput

%x ERROR COMMENT_STATE

%%

<*>"#"					{
					  BEGIN(COMMENT_STATE);
					}
<*>"\n"					{
					  BEGIN(INITIAL);
					}
"inherit-learn"				{
					  return INHERITLEARN;
					}
"inherit-no-learn"			{
					  return INHERITNOLEARN;
					}
"no-learn"				{
					  return NOLEARN;
					}
"dont-reduce-path"			{
					  return DONTREDUCE;
					}
"high-reduce-path"			{
					  return HIGHREDUCE;
					}
"always-reduce-path"			{
					  return ALWAYSREDUCE;
					}
"protected-path"			{
					  return PROTECTED;
					}
"read-protected-path"			{
					  return READPROTECTED;
					}
"high-protected-path"			{
					  return HIGHPROTECTED;
					}
"dont-learn-allowed-ips"		{
					  return NOALLOWEDIPS;
					}
"split-roles"				{
					  return SPLITROLES;
					}
{NUM}					{
					  grlearn_configlval.num = atol(yytext);
					  return NUM;
					}
{FILENAME}				{
					  grlearn_configlval.string = gr_strdup(yytext);
					  return FILENAME;
					}
.					;
%%

void grlearn_configerror(const char *s) { return; }
int grlearn_configwrap(void) { return 1; }
