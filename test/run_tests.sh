#!/bin/bash

function get_test_label 
{
    local RESULT=$1
    if [ $2 -gt 10 -a $1 -lt 10 ]; then
        RESULT=0$RESULT
    fi
    if [ $2 -gt 100 -a $1 -lt 100 ]; then
        RESULT=0$RESULT
    fi
    echo "T$RESULT"
}
function get_nb_messages_sent
{
    local NB_MESSAGES_SENT=0
    local TMP_FILE=`mktemp`
    cat $1 | grep -iE "^((RBCAST)|(ABCAST))" > $TMP_FILE

    while read SCENARIO_LINE
    do
        local SCENARIO_LINE_ITEM=( $SCENARIO_LINE )
        NB_MESSAGES_SENT=`expr $NB_MESSAGES_SENT + ${SCENARIO_LINE_ITEM[1]}`
    done < $TMP_FILE
    rm $TMP_FILE

    echo $NB_MESSAGES_SENT
}

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 TESTS_FILE [mem-check|no-check]"
    exit 1
fi
if [ ! -f $1 ]; then
    echo "First parameter must be a file"
    exit 1
fi

export TIME_FACTOR=1
if [ ${2} == "mem-check" ]; then
    TIME_FACTOR=2
fi

export PRG_PATH=`dirname $0`
export ABSOLUTE_PRG_PATH=`readlink -f $PRG_PATH`
export ABSOLUTE_TESTS_FILE=`readlink -f $1`
export ABSOLUTE_TESTS_DIR=`dirname $ABSOLUTE_TESTS_FILE`

rm -rf $ABSOLUTE_PRG_PATH/output/ 2>/dev/null

export TEST_COUNT=`grep -vE "^#" $ABSOLUTE_TESTS_FILE | wc -l`
export TEST_NUMBER=0
cat $ABSOLUTE_TESTS_FILE | grep -vE "^#" | while read TEST_LINE
do
    # Read and compute the parameters corresponding to the test
    export TEST_PARAMETERS=( $TEST_LINE )
    export MODEL_FILE=$ABSOLUTE_TESTS_DIR/${TEST_PARAMETERS[0]}
    export PROCESSES_FILE=$ABSOLUTE_TESTS_DIR/${TEST_PARAMETERS[1]}
    export PROCESSES_PATH=`dirname $PROCESSES_FILE`

    export TEST_LABEL=$(get_test_label $TEST_NUMBER $TEST_COUNT)

    export ROOT_PATH=$ABSOLUTE_PRG_PATH/output/$TEST_LABEL
    export ERR_PATH=$ROOT_PATH/stderr
    export LOG_PATH=$ROOT_PATH/log
    export LOG_FILE=$ROOT_PATH/log.tar
    export OUT_PATH=$ROOT_PATH/stdout

    # Run the test
    mkdir -p $ERR_PATH
    mkdir -p $LOG_PATH
    mkdir -p $OUT_PATH
    echo "Run test $TEST_LABEL: ${TEST_PARAMETERS[@]}"
    export TMP_PROCESSES_FILE=`mktemp`
    cat $PROCESSES_FILE | grep -vE "^#" | grep -vE "^TRUSTED" > $TMP_PROCESSES_FILE 

    export MAX_NB_MESSAGES_SENT=0
    export TEST_PIDS=( )
    while read PROCESS_LINE
    do
        export PARSED_PROCESS_LINE=`echo $PROCESS_LINE | awk -F\; '{ print $1 " " $2 " " $6 " " $7 }'`
        export PROCESS_PARAMETERS=( $PARSED_PROCESS_LINE )

        export PROCESS_BEHAVIOR="NULL"
        if [ ${PROCESS_PARAMETERS[3]} ]; then
            PROCESS_BEHAVIOR=${PROCESS_PARAMETERS[3]}
        fi

        export INSTANCE_NB_MESSAGES_SENT=$(get_nb_messages_sent $PROCESSES_PATH/${PROCESS_PARAMETERS[2]})
        if [ $INSTANCE_NB_MESSAGES_SENT -gt $MAX_NB_MESSAGES_SENT ]; then
            MAX_NB_MESSAGES_SENT=$INSTANCE_NB_MESSAGES_SENT
        fi

        export TEST_INSTANCE_LABEL=${PROCESS_PARAMETERS[0]#*:}
        $ABSOLUTE_PRG_PATH/run_test.sh ${PROCESS_PARAMETERS[0]} \
            $PROCESSES_PATH/${PROCESS_PARAMETERS[1]} $PROCESSES_PATH/${PROCESS_PARAMETERS[2]} \
            $PROCESS_BEHAVIOR $PROCESSES_FILE $MODEL_FILE \
            $LOG_PATH/$TEST_INSTANCE_LABEL.log $OUT_PATH/$TEST_INSTANCE_LABEL.out $ERR_PATH/$TEST_INSTANCE_LABEL.err \
            $2 & TEST_PIDS+=( "$!" )
    done < $TMP_PROCESSES_FILE
    rm $TMP_PROCESSES_FILE

    # Wait for the end of test
    export MAX_WAIT_ITERATIONS=`expr $TIME_FACTOR \* $MAX_NB_MESSAGES_SENT / 4`
    export WAIT_ITERATION=0;
    export RUNNING=1
    while [ $RUNNING -gt 0 -a $WAIT_ITERATION -lt $MAX_WAIT_ITERATIONS ]; do
        sleep 10s

        RUNNING=0
        for TEST_PID in ${TEST_PIDS[@]}; do
            COUNT=`ps -ef | grep $TEST_PID | grep -v grep | wc -l`
            RUNNING=`expr $RUNNING + $COUNT`
        done
        WAIT_ITERATION=`expr $WAIT_ITERATION + 1`
    done

    # Kill the remainder test
    for TEST_PID in ${TEST_PIDS[@]}; do
        export CHILD_PID=`ps --ppid $TEST_PID -o pid=`
        { kill $TEST_PID && wait $TEST_PID; } 2>/dev/null
        if [ -n $CHILD_PID ]; then
            { kill $CHILD_PID && wait $CHILD_PID; } 2>/dev/null
        fi
    done

    # Compress the log files
    tar -cf $LOG_FILE -C $LOG_PATH .
    gzip $LOG_FILE
    rm -rf $LOG_PATH
    TEST_NUMBER=`expr $TEST_NUMBER + 1`
done
