AC_PREREQ([2.69])
AC_INIT([ExampleApp], [0.1.0], [comunidade@dojot.com])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([-Wall -Werror foreign]) 
# Checks for programs.
AC_PROG_CC

# checks for dependencies
PKG_CHECK_MODULES([MA_COMM], [ma-communication-0.1.0])
PKG_CHECK_MODULES([JSON_C], [json-c])
CFLAGS+=" $MA_COMM_CFLAGS $JSON_C_CFLAGS"
LIBS+=" $MA_COMM_LIBS $JSON_C_LIBS"
PACKAGE_REQUIRES+="ma-communication-0.1.0 json-c-0.13.1"

AC_SUBST([PACKAGE_REQUIRES],[$PACKAGE_REQUIRES])

AC_CONFIG_FILES([Makefile
                 src/Makefile])
AC_OUTPUT
