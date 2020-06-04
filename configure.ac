#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([GPDGC], [1.0], [olivier.rutti@opengroupware.ch])

LIBGPDGC_LT_MAJOR=1
LIBGPDGC_LT_MINOR=0
LIBGPDGC_LT_REVISION=0
AC_SUBST(LIBGPDGC_LT_MAJOR)
AC_SUBST(LIBGPDGC_LT_MINOR)
AC_SUBST(LIBGPDGC_LT_REVISION)

AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_SRCDIR([src/consensus.h])
AC_CONFIG_HEADERS([config.h])

AC_ENABLE_SHARED
AC_DISABLE_STATIC

AM_INIT_AUTOMAKE([subdir-objects])

LT_PREREQ([2.2.6])
LT_INIT([disable-static])

# Checks for programs.
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CPP
AC_PROG_CXX
AC_PROG_INSTALL
AC_PROG_LIBTOOL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_RANLIB

# Checks for libraries.
AC_CHECK_LIB([gcrypt], [gcry_sexp_sprint])
AC_SUBST(GCRYPT_LIBS)

AC_CHECK_LIB([pthread], [pthread_create])
AC_SUBST(PTHREAD_LIBS)

AC_CHECK_LIB([dl], [dlsym])
AC_SUBST(DL_LIBS)

AC_CHECK_LIB([glib-2.0], [g_slist_append])
PKG_CHECK_MODULES(GLIB, glib-2.0)
AC_SUBST(GLIB_LIBS)
AC_SUBST(GLIB_CFLAGS)

# Checks for header files.
AC_CHECK_HEADERS([errno.h arpa/inet.h stdlib.h string.h stdarg.h \
                  dlfcn.h time.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([getpass memset socket strncasecmp strtol])

AC_CONFIG_FILES([Makefile
                 src/Makefile
                 doc/Makefile
                 test/Makefile])
AC_OUTPUT
