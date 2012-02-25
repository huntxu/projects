#! /bin/sh
aclocal || exit 1
autoheader || exit 2
automake --foreign --add-missing --copy || exit 3
autoconf || exit 4

if [ -z "$1" ]; then
    echo "drcom4GDUFS is now prepared to build. Run"
    echo "./configure && make"
    echo
else
    ./configure "$@" || exit 4
fi

