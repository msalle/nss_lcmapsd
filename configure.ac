#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.57])
AC_INIT([nss_lcmapsd], [0.1.0], [msalle@nikhef.nl])
AM_INIT_AUTOMAKE([1.6.3 foreign])

AC_COPYRIGHT([Copyright (c) 2012 Nikhef.
See LICENCE file for details
])

AC_PROG_CC
AC_PROG_LIBTOOL

AC_CHECK_LIB([curl],[curl_easy_init])

AC_CHECK_HEADERS([nss.h])

AC_CONFIG_FILES([Makefile])
AC_CONFIG_HEADERS([nss_lcmapsd_config.h])

if test -d "/lib64" ; then
    NSSMODDIR=/lib64
else
    NSSMODDIR=$libdir
fi
AC_SUBST(NSSMODDIR)

AC_OUTPUT
