##############################################################################
#gradm (c) 2002 Brad Spengler 		                http://grsecurity.net#
#----------------------------				---------------------#
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
#for sparc64
#OPT_FLAGS=-O2 -m64 -mcpu=ultrasparc -mcmodel=medlow -ffixed-g4 \
#	-fcall-used-g5 -fcall-used-g5 -fcall-used-g7 -Wno-sign-compare
OPT_FLAGS=-O2
CFLAGS=$(OPT_FLAGS) -DGRSEC_DIR=\"$(GRSEC_DIR)\"
LDFLAGS=-static		    # must be left as static,otherwise requires 
		            # modification in gradm_adm.c
INSTALL = /usr/bin/install -c

# FHS
MANDIR=/usr/share/man
# older MANDIR
#MANDIR=/usr/man
DESTDIR=

OBJECTS=gradm.tab.o lex.gradm.o learn.tab.o lex.learn.o gradm_misc.o \
	gradm_parse.o gradm_arg.o gradm_pw.o gradm_opt.o gradm_cap.o \
	gradm_sha256.o gradm_adm.o gradm_analyze.o gradm_res.o \
	gradm_human.o gradm_learn.o gradm_net.o gradm_nest.o \
	gradm_sym.o

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

grlearn: grlearn.c
	$(CC) $(CFLAGS) -o $@ grlearn.c $(LIBS) $(LDFLAGS)


gradm.tab.c: gradm.y
	$(USE_YACC) -b gradm -p gradm -d ./gradm.y

lex.gradm.c: gradm.l
	$(USE_LEX) $(LEXFLAGS) -Pgradm ./gradm.l

learn.tab.c: gradm_learner.y
	$(USE_YACC) -b learn -p learn -d ./gradm_learner.y

lex.learn.c: gradm_learner.l
	$(USE_LEX) $(LEXFLAGS) -Plearn ./gradm_learner.l

install: $(GRADM_BIN) gradm.8 acl grlearn
	mkdir -p $(DESTDIR)/sbin
	$(INSTALL) -m 0755 $(GRADM_BIN) $(DESTDIR)/sbin
	$(STRIP) $(DESTDIR)/sbin/$(GRADM_BIN)
	$(INSTALL) -m 0700 grlearn $(DESTDIR)/sbin
	$(STRIP) $(DESTDIR)/sbin/grlearn
	mkdir -p -m 700 $(DESTDIR)$(GRSEC_DIR)
	@if [ ! -f $(DESTDIR)$(GRSEC_DIR)/acl ] ; then \
		$(INSTALL) -m 0600 acl $(DESTDIR)$(GRSEC_DIR) ; \
	fi
	rm -f $(DESTDIR)/dev/grsec
	@if [ ! -e $(DESTDIR)/dev/grsec ] ; then \
		mkdir -p $(DESTDIR)/dev ; \
		$(MKNOD) -m 0622 $(DESTDIR)/dev/grsec c 1 10 ; \
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
