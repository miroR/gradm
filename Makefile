##############################################################################
#gradm (c) 2002,2003,2004 Brad Spengler 	        http://grsecurity.net#
#--------------------------------------			---------------------#
#gradm is licensed under the GNU GPL http://www.gnu.org		             #
##############################################################################

GRADM_BIN=gradm
GRSEC_DIR=/etc/grsec

LEX=/usr/bin/lex
FLEX=/usr/bin/flex
LEXFLAGS=-B
YACC=/usr/bin/yacc
BYACC=/usr/bin/byacc
BISON=/usr/bin/bison
MKNOD=/bin/mknod
#for dietlibc
#CC=/usr/bin/diet /usr/bin/gcc
CC=/usr/bin/gcc
FIND=/usr/bin/find
STRIP=/usr/bin/strip
#for sparc64
#LIBS=
LIBS=-lfl
KERNVER=`uname -r | cut -d"." -f 2`
#for 64-bit archs
#OPT_FLAGS=-O2 -m64
OPT_FLAGS=-O2
CFLAGS=$(OPT_FLAGS) -DGRSEC_DIR=\"$(GRSEC_DIR)\" -DKERNVER=$(KERNVER)
LDFLAGS=
INSTALL = /usr/bin/install -c

# FHS
MANDIR=/usr/share/man
# older MANDIR
#MANDIR=/usr/man
DESTDIR=

OBJECTS=gradm.tab.o lex.gradm.o learn_pass1.tab.o learn_pass2.tab.o \
	fulllearn_pass1.tab.o fulllearn_pass2.tab.o fulllearn_pass3.tab.o \
	gradm_misc.o gradm_parse.o gradm_arg.o gradm_pw.o gradm_opt.o \
	gradm_cap.o gradm_sha256.o gradm_adm.o gradm_analyze.o gradm_res.o \
	gradm_human.o gradm_learn.o gradm_net.o gradm_nest.o \
	gradm_sym.o gradm_newlearn.o gradm_fulllearn.o gradm_lib.o \
	lex.fulllearn_pass1.o lex.fulllearn_pass2.o \
	lex.fulllearn_pass3.o lex.learn_pass1.o lex.learn_pass2.o

all: $(USE_YACC) $(USE_LEX) $(GRADM_BIN) grlearn

USE_YACC = $(shell if [ -x $(BYACC) ]; then echo $(BYACC); \
	else if [ -x $(BISON) ]; then echo $(BISON) -y; \
	else if [ -x $(YACC) ]; then echo $(YACC); \
	else \
		echo "Bison/(b)yacc needs to be installed to compile gradm."; \
		exit 1; \
	fi;fi;fi)

USE_LEX = $(shell if [ -x $(FLEX) ]; then echo $(FLEX); \
	else if [ -x $(LEX) ]; then echo $(LEX); \
	else \
		echo "(f)Lex needs to be installed to compile gradm."; \
		exit 1; \
	fi;fi)

$(GRADM_BIN): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $(OBJECTS) $(LIBS) $(LDFLAGS)

grlearn: grlearn.c gradm_lib.c
	$(CC) $(CFLAGS) -o $@ grlearn.c gradm_lib.c $(LIBS) $(LDFLAGS)


gradm.tab.c: gradm.y
	$(USE_YACC) -b gradm -p gradm -d ./gradm.y

lex.gradm.c: gradm.l
	$(USE_LEX) $(LEXFLAGS) -Pgradm ./gradm.l

fulllearn_pass1.tab.c: gradm_fulllearn_pass1.y
	$(USE_YACC) -b fulllearn_pass1 -p fulllearn_pass1 -d ./gradm_fulllearn_pass1.y
fulllearn_pass2.tab.c: gradm_fulllearn_pass2.y
	$(USE_YACC) -b fulllearn_pass2 -p fulllearn_pass2 -d ./gradm_fulllearn_pass2.y
fulllearn_pass3.tab.c: gradm_fulllearn_pass3.y
	$(USE_YACC) -b fulllearn_pass3 -p fulllearn_pass3 -d ./gradm_fulllearn_pass3.y

lex.fulllearn_pass1.c: gradm_fulllearn_pass1.l
	$(USE_LEX) $(LEXFLAGS) -Pfulllearn_pass1 ./gradm_fulllearn_pass1.l
lex.fulllearn_pass2.c: gradm_fulllearn_pass2.l
	$(USE_LEX) $(LEXFLAGS) -Pfulllearn_pass2 ./gradm_fulllearn_pass2.l
lex.fulllearn_pass3.c: gradm_fulllearn_pass3.l
	$(USE_LEX) $(LEXFLAGS) -Pfulllearn_pass3 ./gradm_fulllearn_pass3.l

learn_pass1.tab.c: gradm_learn_pass1.y
	$(USE_YACC) -b learn_pass1 -p learn_pass1 -d ./gradm_learn_pass1.y
learn_pass2.tab.c: gradm_learn_pass2.y
	$(USE_YACC) -b learn_pass2 -p learn_pass2 -d ./gradm_learn_pass2.y

lex.learn_pass1.c: gradm_learn_pass1.l
	$(USE_LEX) $(LEXFLAGS) -Plearn_pass1 ./gradm_learn_pass1.l
lex.learn_pass2.c: gradm_learn_pass2.l
	$(USE_LEX) $(LEXFLAGS) -Plearn_pass2 ./gradm_learn_pass2.l

install: $(GRADM_BIN) gradm.8 policy grlearn
	mkdir -p $(DESTDIR)/sbin
	$(INSTALL) -m 0755 $(GRADM_BIN) $(DESTDIR)/sbin
	$(STRIP) $(DESTDIR)/sbin/$(GRADM_BIN)
	$(INSTALL) -m 0700 grlearn $(DESTDIR)/sbin
	$(STRIP) $(DESTDIR)/sbin/grlearn
	mkdir -p -m 700 $(DESTDIR)$(GRSEC_DIR)
	@if [ ! -f $(DESTDIR)$(GRSEC_DIR)/policy ] ; then \
		if [ ! -f $(DESTDIR)$(GRSEC_DIR)/acl ] ; then \
			mv $(DESTDIR)$(GRSEC_DIR)/acl $(DESTDIR)$(GRSEC_DIR)/policy ; \
		else \
			$(INSTALL) -m 0600 policy $(DESTDIR)$(GRSEC_DIR) ; \
		fi \
	fi
	@if [ -z "`cut -d" " -f3 /proc/mounts | grep "^devfs"`" ] ; then \
		rm -f $(DESTDIR)/dev/grsec ; \
		if [ ! -e $(DESTDIR)/dev/grsec ] ; then \
			mkdir -p $(DESTDIR)/dev ; \
			$(MKNOD) -m 0622 $(DESTDIR)/dev/grsec c 1 12 ; \
		fi \
	fi
	mkdir -p $(DESTDIR)$(MANDIR)/man8
	$(INSTALL) -m 0644 gradm.8 $(DESTDIR)$(MANDIR)/man8/$(GRADM_BIN).8
	@if [ -z $(DESTDIR) ] ; then \
		if [ -x /sbin/$(GRADM_BIN) ] ; then \
			$(FIND) $(GRSEC_DIR) -type f -name pw -size 48c -exec rm -f $(GRSEC_DIR)/pw \; ; \
			if [ ! -f $(GRSEC_DIR)/pw ] ; then \
				/sbin/$(GRADM_BIN) -P ; \
                        fi \
		fi \
	fi

clean:
	rm -f core *.o $(GRADM_BIN) lex.*.c *.tab.c *.tab.h grlearn
