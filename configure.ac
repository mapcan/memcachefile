AC_PREREQ(2.61)
AC_INIT([memcachefile], [1.0.0], [fuckme@gmail.com])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_PROG_CC
AM_PROG_CC_C_O
AC_CONFIG_HEADERS([config.h])

trylibeventdir=""
AC_ARG_WITH(libevent,
       [  --with-libevent=PATH    Specify path to libevent installation ],
       [
                if test "x$withval" != "xno" ; then
                        trylibeventdir=$withval
                fi
       ]
)

dnl ------------------------------------------------------
dnl libevent detection.  swiped from Tor.  modified a bit.

LIBEVENT_URL=http://www.monkey.org/~provos/libevent/

AC_CACHE_CHECK([for libevent directory], ac_cv_libevent_dir, [
  saved_LIBS="$LIBS"
  saved_LDFLAGS="$LDFLAGS"
  saved_CPPFLAGS="$CPPFLAGS"
  le_found=no
  for ledir in $trylibeventdir "" $prefix /usr/local ; do
    LDFLAGS="$saved_LDFLAGS"
    LIBS="$saved_LIBS -levent"

    # Skip the directory if it isn't there.
    if test ! -z "$ledir" -a ! -d "$ledir" ; then
       continue;
    fi
    if test ! -z "$ledir" ; then
      if test -d "$ledir/lib" ; then
        LDFLAGS="-L$ledir/lib $LDFLAGS"
      else
        LDFLAGS="-L$ledir $LDFLAGS"
      fi
      if test -d "$ledir/include" ; then
        CPPFLAGS="-I$ledir/include $CPPFLAGS"
      else
        CPPFLAGS="-I$ledir $CPPFLAGS"
      fi
    fi
    # Can I compile and link it?
    AC_TRY_LINK([#include <sys/time.h>
#include <sys/types.h>
#include <event.h>], [ event_init(); ],
       [ libevent_linked=yes ], [ libevent_linked=no ])
    if test $libevent_linked = yes; then
       if test ! -z "$ledir" ; then
         ac_cv_libevent_dir=$ledir
       else
         ac_cv_libevent_dir="(system)"
       fi
       le_found=yes
       break
    fi
  done
  LIBS="$saved_LIBS"
  LDFLAGS="$saved_LDFLAGS"
  CPPFLAGS="$saved_CPPFLAGS"
  if test $le_found = no ; then
    AC_MSG_ERROR([libevent is required.  You can get it from $LIBEVENT_URL

      If it's already installed, specify its path using --with-libevent=/dir/
])
  fi
])
LIBS="$LIBS -levent"
if test $ac_cv_libevent_dir != "(system)"; then
  if test -d "$ac_cv_libevent_dir/lib" ; then
    LDFLAGS="-L$ac_cv_libevent_dir/lib $LDFLAGS"
    le_libdir="$ac_cv_libevent_dir/lib"
  else
    LDFLAGS="-L$ac_cv_libevent_dir $LDFLAGS"
    le_libdir="$ac_cv_libevent_dir"
  fi
  if test -d "$ac_cv_libevent_dir/include" ; then
    CPPFLAGS="-I$ac_cv_libevent_dir/include $CPPFLAGS"
  else
    CPPFLAGS="-I$ac_cv_libevent_dir $CPPFLAGS"
  fi
fi

#dnl Check BerkeleyDB lib and headers
#bdbdir="/usr/local/BerkeleyDB.4.7"
#AC_ARG_WITH(bdb,
#       [  --with-bdb=PATH         Specify path to BerkeleyDB installation ],
#       [
#                if test "x$withval" != "xno" ; then
#                        bdbdir=$withval
#                fi
#       ]
#)
#CPPFLAGS="-I$bdbdir/include $CPPFLAGS"
#LDFLAGS="-L$bdbdir/lib $LDFLAGS"
#AC_SEARCH_LIBS([db_create], [db], [] ,[AC_MSG_ERROR(cannot find libdb.so in $bdbdir/lib)])
#AC_CHECK_HEADERS([db.h], [] ,[AC_MSG_ERROR(cannot find db.h in $bdbdir/include)])

dnl ----------------------------------------------------------------------------

AC_SEARCH_LIBS(socket, socket)
AC_SEARCH_LIBS(gethostbyname, nsl)
AC_SEARCH_LIBS(mallinfo, malloc)

AC_CHECK_FUNC(daemon,AC_DEFINE([HAVE_DAEMON],,[Define this if you have daemon()]),[AC_LIBOBJ(daemon)])

AC_HEADER_STDBOOL
AC_C_CONST
AC_CHECK_HEADER(malloc.h, AC_DEFINE(HAVE_MALLOC_H,,[do we have malloc.h?]))
AC_CHECK_MEMBER([struct mallinfo.arena], [
        AC_DEFINE(HAVE_STRUCT_MALLINFO,,[do we have stuct mallinfo?])
    ], ,[
#    include <malloc.h>
    ]
)

dnl From licq: Copyright (c) 2000 Dirk Mueller
dnl Check if the type socklen_t is defined anywhere
AC_DEFUN([AC_C_SOCKLEN_T],
[AC_CACHE_CHECK(for socklen_t, ac_cv_c_socklen_t,
[
  AC_TRY_COMPILE([
    #include <sys/types.h>
    #include <sys/socket.h>
  ],[
    socklen_t foo;
  ],[
    ac_cv_c_socklen_t=yes
  ],[
    ac_cv_c_socklen_t=no
  ])
])
if test $ac_cv_c_socklen_t = no; then
  AC_DEFINE(socklen_t, int, [define to int if socklen_t not available])
fi
])

AC_C_SOCKLEN_T

dnl Check whether the user wants threads or not
AC_ARG_ENABLE(threads,
  [AS_HELP_STRING([--enable-threads],[support multithreaded execution])])
if test "x$enable_threads" == "xyes"; then
  AC_SEARCH_LIBS([pthread_create], [pthread], [AC_DEFINE([USE_THREADS],,[Define this if you want to use pthreads])] ,[AC_MSG_ERROR(cannot find libpthread.so)])
fi

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
