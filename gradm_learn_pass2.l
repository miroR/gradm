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
#include "learn_pass2.tab.h"

void learn_pass2error(const char *s);
int learn_pass2wrap(void);

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
					  learn_pass2lval.num = USER;
					  return USER;
					}
"g"					{
					  learn_pass2lval.num = GROUP;
					  return GROUP;
					}
{NUM}					{
					  learn_pass2lval.num = atol(yytext);
					  return NUM;
					}
{NOTAFILE}				{
					  learn_pass2lval.string = gr_strdup("/proc");
					  return FILENAME;
					}
{ROLENAME}				{
					  learn_pass2lval.string = gr_strdup(yytext);
					  return ROLENAME;
					}
{FILENAME}				{
					  learn_pass2lval.string = gr_strdup(yytext);
					  return FILENAME;
					}
{IPADDR}				{
					  if (inet_aton(yytext, &ip))
						learn_pass2lval.num = ip.s_addr;
					  else
						learn_pass2lval.num = 0;
					  return IPADDR;
					}
[\t]					{ return ':'; }
.					;
%%

void learn_pass2error(const char *s) { return; }
int learn_pass2wrap(void) { return 1; }
