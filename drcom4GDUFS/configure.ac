#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.64])
AC_INIT([drcom4GDUFS], [1.1], [mhuntxu@gmail.com])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_MAKE_SET
AC_CHECK_PROGS([DHCLIENT], [dhclient], [:])
if test "$DHCLIENT" = :; then
    AC_MSG_WARN([dhclient not found, you may need to specify your own dhcp command.])
fi
AC_CHECK_PROGS([PCAPCONFIG], [pcap-config], [:])
if test "$PCAPCONFIG" = :; then
    AC_MSG_WARN([pcap-config not found!])
    export PCAPLIBS="-lpcap"
    export PCAPCFLAGS="-I/usr/include"
else
    export PCAPLIBS="`pcap-config --libs`"
    export PCAPCFLAGS="`pcap-config --cflags`"
fi
AC_SUBST([PCAPLIBS])
AC_SUBST([PCAPCFLAGS])

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h netinet/in.h stdlib.h string.h sys/ioctl.h sys/socket.h termios.h unistd.h])
AC_CHECK_HEADER([pcap.h], [], [PCAPHEADER=:])
if test "$PCAPHEADER" = :; then
    AC_MSG_ERROR([pcap.h not found!])
fi

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_PID_T
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_FORK
AC_CHECK_FUNCS([alarm bzero dup2 ftruncate gethostname memset socket])

AC_CONFIG_FILES([Makefile
                 src/Makefile])
AC_OUTPUT

