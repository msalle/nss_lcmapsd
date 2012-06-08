#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.57])
AC_INIT([nss_lcmapsd], [0.1.3], [msalle@nikhef.nl])
AM_INIT_AUTOMAKE([1.6.3 foreign])

AC_COPYRIGHT([Copyright (c) 2011 Nikhef.
See LICENCE file for details
])

AC_PROG_CC
AC_PROG_LIBTOOL

AC_CHECK_LIB([curl],[curl_easy_init])

AC_CONFIG_FILES([Makefile])
AC_CONFIG_HEADERS([nss_lcmapsd_config.h])

AC_OUTPUT
