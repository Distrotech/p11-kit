
include $(top_srcdir)/build/Makefile.tests

NULL =

INCLUDES = \
	-I$(top_srcdir) \
	-I$(srcdir)/.. \
	-I$(top_srcdir)/common \
	$(CUTEST_CFLAGS)

noinst_LTLIBRARIES = \
	libtestdata.la

libtestdata_la_SOURCES = \
	test-data.c test-data.h

LDADD = \
	$(top_builddir)/trust/libtrust-testable.la \
	$(top_builddir)/common/libp11-data.la \
	$(top_builddir)/common/libp11-library.la \
	$(top_builddir)/common/libp11-compat.la \
	$(builddir)/libtestdata.la \
	$(LIBTASN1_LIBS) \
	$(CUTEST_LIBS) \
	$(NULL)

CHECK_PROGS = \
	test-parser \
	test-token \
	test-session \
	test-module \
	$(NULL)

noinst_PROGRAMS = \
	$(CHECK_PROGS)

TESTS = $(CHECK_PROGS:=$(EXEEXT))

EXTRA_DIST = \
	anchors \
	certificates \
	files \
	$(NULL)