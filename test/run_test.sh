#!/bin/bash

if [ "$#" -ne 10 ]; then
    echo "Illegal number of parameters"
    exit 1
fi
if [ ! -f $2 ]; then
    echo "Second parameter must be a file"
    exit 1
fi
if [ ! -f $3 ]; then
    echo "Third parameter must be a file"
    exit 1
fi
if [ ! -f $5 ]; then
    echo "Fifth parameter must be a file"
    exit 1
fi
if [ ! -f $6 ]; then
    echo "Sixth parameter must be a file"
    exit 1
fi

export PRG_PATH=`dirname $0`
export LD_LIBRARY_PATH=$PRG_PATH/../src/.libs

if [[ $4 =~ "corrupted" ]]; then
    export LD_PRELOAD=$PRG_PATH/.libs/libcorrupted.so
elif [[ $4 =~ "malicious" ]]; then
    export LD_PRELOAD=$PRG_PATH/.libs/libmalicious.so
elif [[ $4 =~ "fakedecider" ]]; then
    export LD_PRELOAD=$PRG_PATH/.libs/libfakedecider.so
elif [ $4 != "NULL" ]; then
    echo "Invalid behavior"
    exit 1
fi 

if [ ${10} = "mem-check" ]; then
    valgrind --tool=memcheck --track-origins=yes --leak-check=full --num-callers=30 $PRG_PATH/gpdgc_instance_test $1 $2 $3 $5 $6 $7 >>$8 2>>$9
else
    $PRG_PATH/gpdgc_instance_test $1 $2 $3 $5 $6 $7 >>$8 2>>$9
fi
