## RDKSSA Support

if !RDKSSA_UT_ENABLED
AM_CFLAGS = -I$(top_srcdir)/ssa_top/ssa_oss/ssa_common -DRDKSSA_ERROR_ENABLED -DRDKSSA_LOG_FILE $(CFLAGS) -Werror -Wall -Os
#AM_CFLAGS += -DRDKSSA_INFO_ENABLED -DRDKSSA_DEBUG_ENABLED
OBJCOPY = objcopy
bin_PROGRAMS = ssacli
ssacli_SOURCES = ssacli.c
ssacli_LDADD = $(top_builddir)/ssa_top/ssa_oss/ssa_common/libssa.la
ssacli_CFLAGS = $(AM_CFLAGS)
else
AM_CFLAGS = -I$(top_srcdir)/ssa_top/ssa_oss/ssa_common -DUNIT_TESTS -Wfatal-errors -DRDKSSA_ERROR_ENABLED -Werror -Wall -Wno-unused-function
AM_CFLAGS += -DRDKSSA_INFO_ENABLED -DRDKSSA_DEBUG_ENABLED
OBJCOPY = objcopy
bin_PROGRAMS = ut_ssacli
ut_ssacli_SOURCES = ssacli.c
ut_ssacli_CFLAGS = $(AM_CFLAGS)
endif
