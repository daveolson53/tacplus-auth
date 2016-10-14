#  Copyright 2016 Cumulus Networks, Inc.  All rights reserved.
#  Dave Olson <olson@cumulusnetworks.com>

EXTRA_DIST = ChangeLog README

tacplus_auth_SOURCES = tacplus-auth.c
tacplus_auth_CFLAGS = -O -Wall -Werror
tacplus_auth_LDADD = -ltac -laudit
sbin_PROGRAMS = tacplus-auth
man_MANS = tacplus-auth.8

clean-generic:
	rm -rf autom4te*.cache 
	rm -f *.rej *.orig *.lang

ACLOCAL_AMFLAGS = -I config

MAINTAINERCLEANFILES = Makefile.in config.h.in configure aclocal.m4 \
                       config/config.guess  config/config.sub  config/depcomp \
                       config/install-sh config/ltmain.sh config/missing

install-exec-hook:
	chown root.root $(DESTDIR)$(sbindir)/tacplus-auth
	chmod 4755 $(DESTDIR)$(sbindir)/tacplus-auth
