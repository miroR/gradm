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
#include "fulllearn_pass2.tab.h"

void fulllearn_pass2error(const char *s);
int fulllearn_pass2wrap(void);

static struct in_addr ip;
%}

ROLENAME ^[_a-zA-Z0-9.-]{1,64}
NOTAFILE [a-z]+"["[0-9]+"]"
NUM [-]?[0-9]+
FILENAME [/][^\t\n]*
IPADDR [0-9]{1,3}"."[0-9]{1,3}"."[0-9]{1,3}"."[0-9]{1,3}

%option nounput

%x ERROR

%%

"u"					{
					  fulllearn_pass2lval.num = USER;
					  return USER;
					}
"g"					{
					  fulllearn_pass2lval.num = GROUP;
					  return GROUP;
					}
{NUM}					{
					  fulllearn_pass2lval.num = atol(yytext);
					  return NUM;
					}
{NOTAFILE}				{
					  fulllearn_pass2lval.string = gr_strdup("/proc");
					  return FILENAME;
					}
{ROLENAME}				{
					  /* not used in grammar */
					  return ROLENAME;
					}
{FILENAME}				{
					  fulllearn_pass2lval.string = gr_strdup(yytext);
					  return FILENAME;
					}
{IPADDR}				{
					  if (inet_aton(yytext, &ip))
						fulllearn_pass2lval.num = ip.s_addr;
					  else
						fulllearn_pass2lval.num = 0;
					  return IPADDR;
					}
[\t]					{ return ':'; }
.					;
%%

void fulllearn_pass2error(const char *s) { return; }
int fulllearn_pass2wrap(void) { return 1; }
