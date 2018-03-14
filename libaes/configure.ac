AC_INIT([aes], [0.1.0], [comunidade@dojot.com.br])
AC_PREREQ([2.69])
AC_CONFIG_HEADERS([config.h])

AC_CONFIG_AUX_DIR(aux-dist)
AC_CONFIG_MACRO_DIR([aux-dist/m4])
AM_INIT_AUTOMAKE([-Wall -Werror foreign]) 


CFLAGS+="  "
LIBS+="  "

PACKAGE_REQUIRES=""
AC_SUBST([PACKAGE_REQUIRES],[$PACKAGE_REQUIRES])

PACKAGE_DESCRIPTION=""
AC_SUBST([PACKAGE_DESCRIPTION], [${PACKAGE_DESCRIPTION}])

AC_ARG_WITH([debug], AS_HELP_STRING([--with-debug], [Build with debugging symbols and without optimization]))
if test "x$with_debug" = "xyes";
then
    CFLAGS+=" -g3 -O0 "
    CXXFLAGS+=" -g3 -O0 "
fi
AM_CONDITIONAL([BUILD_WITH_DEBUG], [ test "x$with_debug" = "xyes" ])


AC_CONFIG_FILES([Makefile
				 ${PACKAGE_NAME}-${PACKAGE_VERSION}.pc:pc.in
                 src/Makefile])
                 
AC_PROG_CC
AM_PROG_AR
LT_INIT([dlopen shared])

AC_OUTPUT
