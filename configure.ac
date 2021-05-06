AC_PREREQ([2.65])
AC_INIT([rdkssa], [1.0], [BUG-REPORT-ADDRESS])
AC_CONFIG_SRCDIR([])

AC_ENABLE_SHARED
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([foreign])

LT_INIT

# Checks for following programs.
AC_PROG_CC
AM_PROG_CC_C_O
AM_PROG_LIBTOOL(libtool)
AC_PROG_INSTALL

# Checks for following header files.
AC_CHECK_HEADERS([fcntl.h stdlib.h string.h unistd.h stdio.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_HEADER_STDBOOL

# Checks for library functions.
C_FUNC_MALLOC
AC_CONFIG_FILES([Makefile
        ssa_top/Makefile
        ssa_top/ssa_oss/Makefile 
	ssa_top/ssa_oss/ssa_common/Makefile
	ssa_top/ssa_oss/ssa_common/providers/Makefile
	ssa_top/ssa_oss/ssa_common/providers/Mount/Makefile
	ssa_top/ssa_oss/ssa_common/providers/Mount/generic/Makefile
	ssa_top/ssa_oss/cli/Makefile])

AM_CONDITIONAL([RDKSSA_UT_ENABLED], [test $RDKSSA_UT_ENABLED = yes])
AC_OUTPUT
