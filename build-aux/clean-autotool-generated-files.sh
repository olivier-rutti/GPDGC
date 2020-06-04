#!/bin/sh

export CUR_PATH=`pwd`
export PRG_PATH=`dirname $0`

cd $PRG_PATH/..
make clean
rm -rf autom4te.cache/ aclocal.m4 autoscan.log config.* configure \
    libtool stamp-h1 Makefile Makefile.in \
    src/.deps src/Makefile.in src/Makefile \
    test/src/.deps test/Makefile.in test/Makefile \
    doc/Makefile.in doc/Makefile
cd $CUR_PATH
