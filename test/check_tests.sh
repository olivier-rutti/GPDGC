#!/bin/bash

function array_contains
{
    local N=$#
    local VALUE=${!N}
    local ITERATOR=1

    while [ $ITERATOR -lt $# ]; do
        if [ "${!ITERATOR}" == "${VALUE}" ]; then
            echo "y"
            exit 0
        fi
        ITERATOR=`expr $ITERATOR + 1`
    done
    echo "n"
}
function format_log_number
{
    local RESULT=""
    local LOG=1
    local COUNTER=1

    while [ $COUNTER -le $2 ]; do
        if [ $1 -ge $LOG ]; then
            if [ $1 -ge $4 ]; then
                RESULT="${RED}+$RESULT"
            elif [ $1 -ge $3 ]; then
                RESULT="${ORANGE}+$RESULT"
            else
                RESULT="${GREEN}+$RESULT"
            fi
        else
            RESULT="${GREEN}-$RESULT"
        fi

        COUNTER=`expr $COUNTER + 1`
        LOG=`expr $LOG \* 10`
    done

    echo $RESULT
    exit 0
}
function format_time_number
{
    local RESULT=`echo "000000000000000000000000000000$1" | tail -c $2`
    if [ $1 -ge $4 ]; then
        RESULT="${RED}$RESULT"
    elif [ $1 -ge $3 ]; then
        RESULT="${ORANGE}$RESULT"
    else
        RESULT="${GREEN}$RESULT"
    fi

    echo $RESULT
    exit 0
}
function get_corresponding_chunk
{
    local HEAD=`head -n 1 $3 | awk -Fed: '{ print $2 }'`
    for RESULT_CHUNK in $1/${2}.part*; do
        local RESULT_HEAD=`head -n 1 $RESULT_CHUNK | awk -Fed: '{ print $2 }'`

        if [ "$HEAD" == "$RESULT_HEAD" ]; then
            echo $RESULT_CHUNK
        fi
    done
}
function get_nb_key_changes
{
    local RESULT=1
    while read PROCESS_LINE
    do
        local PARSED_PROCESS_LINE=`echo $PROCESS_LINE | awk -F\; '{ print $1 " " $4 " " $6 " " $7 }'`
        local PROCESS_PARAMETERS=( $PARSED_PROCESS_LINE )

        local PROCESS_SCENARIO=`dirname $1`"/"`echo ${PROCESS_PARAMETERS[2]}`
        local KEY_CHANGES=`grep -i UPDATE-KEY $PROCESS_SCENARIO | wc -l`

        RESULT=`expr $RESULT + $KEY_CHANGES`
    done < $1

    echo $RESULT
}
function get_nb_view_changes
{
    local RESULT=1                              # INCLUDE INITIAL VIEW !!
    while read PROCESS_LINE
    do
        local PARSED_PROCESS_LINE=`echo $PROCESS_LINE | awk -F\; '{ print $1 " " $4 " " $6 " " $7 }'`
        local PROCESS_PARAMETERS=( $PARSED_PROCESS_LINE )

        local PROCESS_SCENARIO=`dirname $1`"/"`echo ${PROCESS_PARAMETERS[2]}`
        local VIEW_CHANGES=`grep -iE "(ADD|REMOVE)" $PROCESS_SCENARIO | wc -l`

        RESULT=`expr $RESULT + $VIEW_CHANGES`
    done < $1

    echo $RESULT
}
function get_process_msgs
{
    local DELIVER_REGEX="^((RBCAST)|(ABCAST))"
    while read PROCESS_LINE
    do
        local PARSED_PROCESS_LINE=`echo $PROCESS_LINE | awk -F\; '{ print $1 " " $4 " " $6 " " $7 }'`
        local PROCESS_PARAMETERS=( $PARSED_PROCESS_LINE )

        local PROCESS_SCENARIO=`dirname $1`"/"`echo ${PROCESS_PARAMETERS[2]}`
        local PROCESS_MSGS=0
        local NB_MSGS=( `cat $PROCESS_SCENARIO | grep -iE "$DELIVER_REGEX" | awk '{ printf "%d ", $2 }'` )

        for NB_MSG in "${NB_MSGS[@]}"; do
            PROCESS_MSGS=`expr $PROCESS_MSGS + $NB_MSG`
        done

        echo -n "$PROCESS_MSGS "
    done < $1
}
function get_process_ports
{
    while read PROCESS_LINE
    do
        local PARSED_PROCESS_LINE=`echo $PROCESS_LINE | awk -F\; '{ print $1 " " $4 " " $6 " " $7 }'`
        local PROCESS_PARAMETERS=( $PARSED_PROCESS_LINE )

        local PROCESS_PORT=`echo ${PROCESS_PARAMETERS[0]} | awk -F\: '{ print $2 }'`
        echo -n "$PROCESS_PORT "
    done < $1
}
function get_process_types
{
    local TMP_FILE=`mktemp`
    local SCENARIO_DIRNAME=`dirname $1`
    local ALL_SCENARIOS=( `cat $1 | awk -F\; '{ printf "%s ", $6 }'` )
    (for SCENARIO in "${ALL_SCENARIOS[@]}"; do grep -i Remove $SCENARIO_DIRNAME/$SCENARIO; done) > $TMP_FILE

    while read PROCESS_LINE
    do
        local PARSED_PROCESS_LINE=`echo $PROCESS_LINE | awk -F\; '{ print $1 " " $4 " " $6 " " $7 }'`
        local PROCESS_PARAMETERS=( $PARSED_PROCESS_LINE )

        local PROCESS_SCENARIO=`dirname $1`"/"`echo ${PROCESS_PARAMETERS[2]}`
        if  [[ ${PROCESS_PARAMETERS[3]} =~ "corrupted" ]] ||
            [[ ${PROCESS_PARAMETERS[3]} =~ "malicious" ]] ||
            [[ ${PROCESS_PARAMETERS[3]} =~ "fakedecider" ]]; then
            echo -n "B "
        elif [ `grep -i "crash" $PROCESS_SCENARIO | wc -l` -gt 0 ]; then
            echo -n "F "
        elif [ `grep ${PROCESS_PARAMETERS[0]} $TMP_FILE | wc -l` -gt 0 ]; then
            echo -n "R "
        elif [ ${PROCESS_PARAMETERS[1]} = "C" ]; then
            echo -n "C "
        elif [ ${PROCESS_PARAMETERS[1]} = "L" ]; then
            echo -n "A "
        else
            echo -n "S "
        fi
    done < $1
    rm $TMP_FILE
}
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
export DELIVER_REGEX="((ADELIVER)|(RDELIVER))"

export GREEN='\033[0;32m'
export YELLOW='\033[1;32m'
export ORANGE='\033[0;33m'
export RED='\033[0;31m'
export NC='\033[0m' # No Color

export PRG_PATH=`dirname $0`
export ABSOLUTE_PRG_PATH=`readlink -f $PRG_PATH`
export ABSOLUTE_TESTS_FILE=`readlink -f $1`
export ABSOLUTE_TESTS_DIR=`dirname $ABSOLUTE_TESTS_FILE`
export ABSOLUTE_TMP_PATH=`mktemp -d`
mkdir -p $ABSOLUTE_TMP_PATH

export TEST_COUNT=`grep -vE "^#" $ABSOLUTE_TESTS_FILE | wc -l`
export TEST_NUMBER=0
cat $ABSOLUTE_TESTS_FILE | grep -vE "^#" | while read TEST_LINE
do
    # Read and compute the parameters corresponding to the test
    export TEST_PARAMETERS=( $TEST_LINE )
    export MODEL_FILE=$ABSOLUTE_TESTS_DIR/${TEST_PARAMETERS[0]}

    export PROCESSES_FILE=$ABSOLUTE_TESTS_DIR/${TEST_PARAMETERS[1]}
    export PROCESS_PORTS=( $(get_process_ports $PROCESSES_FILE) )
    export PROCESS_TYPES=( $(get_process_types $PROCESSES_FILE) )
    export PROCESS_MSGS=( $(get_process_msgs $PROCESSES_FILE $MODEL_FILE) )

    export NB_PROCESSES=${#PROCESS_PORTS[@]}
    export NB_KEY_CHANGES=$(get_nb_key_changes $PROCESSES_FILE)
    export NB_VIEW_CHANGES=$(get_nb_view_changes $PROCESSES_FILE)
    
    export NB_TOTAL_MESSAGES=0
    export COUNTER=0
    while [ $COUNTER -lt $NB_PROCESSES ]; do
        export TYPE=${PROCESS_TYPES[$COUNTER]}
        export MSG=${PROCESS_MSGS[$COUNTER]}
        COUNTER=`expr $COUNTER + 1`

        if [ $TYPE == "S" ] || [ $TYPE == "A" ] || [ $TYPE == "C" ]; then
            NB_TOTAL_MESSAGES=`expr $NB_TOTAL_MESSAGES + $MSG`
        fi
    done
    export WARNING_TIME=`expr $NB_TOTAL_MESSAGES / 12 \* $TIME_FACTOR`
    export ERROR_TIME=`expr $WARNING_TIME \* 6`

    # Compute and display test Label
    export TEST_LABEL=$(get_test_label $TEST_NUMBER $TEST_COUNT)
    export ERR_PATH=$ABSOLUTE_PRG_PATH/output/$TEST_LABEL/stderr
    export LOG_FILE=$ABSOLUTE_PRG_PATH/output/$TEST_LABEL/log.tar.gz
    export OUT_PATH=$ABSOLUTE_PRG_PATH/output/$TEST_LABEL/stdout
    export TEST_TMP_PATH=$ABSOLUTE_TMP_PATH/$TEST_LABEL
    export LOG_PATH=$TEST_TMP_PATH/log
    
    mkdir -p $LOG_PATH
    tar -xzvf $LOG_FILE -C $LOG_PATH >/dev/null 2>/dev/null

    # Compute the reference process and the output per view for each process
    export REFERENCE_SERVER=
    export COUNTER=0
    while [ $COUNTER -lt $NB_PROCESSES ]; do
        export PROCESS=${PROCESS_PORTS[$COUNTER]}
        export TYPE=${PROCESS_TYPES[$COUNTER]}
        COUNTER=`expr $COUNTER + 1`

        if [ $TYPE == "S" ]; then
            REFERENCE_SERVER=$PROCESS
        fi

        export OUTPUT_FILE=${OUT_PATH}/$PROCESS.out
        if [ -f $OUTPUT_FILE ]; then
            csplit -sz -f ${TEST_TMP_PATH}/${PROCESS}.part $OUTPUT_FILE "/iew has been/" {*} 2>/dev/null
            for PART_FILE in `ls ${TEST_TMP_PATH}/${PROCESS}.part* 2>/dev/null`; do
                if [ `grep -iE "$DELIVER_REGEX" $PART_FILE | wc -l` -le 1 ]; then
                    rm $PART_FILE
                fi
            done
        fi
    done

    # Check Completeness, Order, Duration and Memory
    export COUNTER=0
    export LIVENESS_CHECK=""
    export SAFETY_CHECK=""
    export MANAGEMENT_CHECK=""
    export MEMORY_CHECK=""
    export MINIMUM_DURATION=9999
    export MAXIMUM_DURATION=0
    export CLIENT_SIGN="|"
    while [ $COUNTER -lt $NB_PROCESSES ]; do
        export PROCESS=${PROCESS_PORTS[$COUNTER]}
        export TYPE=${PROCESS_TYPES[$COUNTER]}
        export MSG=${PROCESS_MSGS[$COUNTER]}
        export ERR_FILE=${ERR_PATH}/${PROCESS}.err
        export LOG_FILE=${LOG_PATH}/${PROCESS}.log
        export OUT_FILE=${OUT_PATH}/${PROCESS}.out
        COUNTER=`expr $COUNTER + 1`

        if [ $TYPE == "C" ]; then
            LIVENESS_CHECK=${LIVENESS_CHECK}${NC}${CLIENT_SIGN}
            SAFETY_CHECK=${SAFETY_CHECK}${NC}${CLIENT_SIGN}
            MANAGEMENT_CHECK=${MANAGEMENT_CHECK}${NC}${CLIENT_SIGN}
            MEMORY_CHECK=${MEMORY_CHECK}${NC}${CLIENT_SIGN}
            CLIENT_SIGN=""
        fi

        if [ -f $ERR_FILE ] && [ -f $LOG_FILE ] && [ -f $OUT_FILE ] && [ -n "$REFERENCE_SERVER" ]; then

            # Compute Test Duration
            export START_TIME=`head -n 1 $LOG_FILE | awk '{ print $2 " " $3 " " $4 }'`
            export START_SECOND=`date --date="$START_TIME" +%s`
            export END_TIME=`tail -n 1 $LOG_FILE | awk '{ print $2 " " $3 " " $4 }'`
            export END_SECOND=`date --date="$END_TIME" +%s`
            export DURATION=`expr $END_SECOND - $START_SECOND`
            if [ $TYPE == "S" ] || [ $TYPE == "A" ] || [ $TYPE == "C" ]; then
                if [ $MINIMUM_DURATION -gt $DURATION ]; then MINIMUM_DURATION=$DURATION; fi
                if [ $MAXIMUM_DURATION -lt $DURATION ]; then MAXIMUM_DURATION=$DURATION; fi
            fi

            # Compute Liveness: correct servers should receives all messages issued by correct processes
            #                   correct processes should stop normally
            export TERMINATED=`grep "Close program" ${OUT_FILE}`
            if [ $TYPE == "C" ]; then
                export NB_REPLIES=`grep -i "Deliver reply" $OUT_FILE | wc -l`
                if [ $NB_REPLIES -ne $MSG ]; then
                    LIVENESS_CHECK=${LIVENESS_CHECK}${RED}U
                elif [ -n "$TERMINATED" ]; then
                    LIVENESS_CHECK=${LIVENESS_CHECK}${GREEN}O
                else
                    LIVENESS_CHECK=${LIVENESS_CHECK}${ORANGE}B
                fi
            elif [ $TYPE == "S" ]; then
                export HAS_RECEIVED_ALL_MESSAGES="y"
                export INNER_COUNTER=0
                while [ $INNER_COUNTER -lt $NB_PROCESSES ]; do
                    export INNER_PROCESS=${PROCESS_PORTS[$INNER_COUNTER]}
                    export INNER_TYPE=${PROCESS_TYPES[$INNER_COUNTER]}
                    export INNER_MSG=${PROCESS_MSGS[$INNER_COUNTER]}
                    INNER_COUNTER=`expr $INNER_COUNTER + 1`

                    if [ $INNER_TYPE == "S" ] || [ $INNER_TYPE == "A" ] || [ $INNER_TYPE == "C" ]; then
                        if [ $INNER_MSG -ne `grep "by '127.0.0.1:$INNER_PROCESS:" $OUT_FILE | wc -l` ]; then
                            HAS_RECEIVED_ALL_MESSAGES="n"
                        fi
                    fi
                done

                export LAST_CONSENSUS_TIME=`grep Decides $LOG_FILE | tail -n 1 | awk '{ print $2 " " $3 " " $4 }'`
                export LAST_CONSENSUS_SECOND=`date --date="$LAST_CONSENSUS_TIME" +%s`
                if [ $HAS_RECEIVED_ALL_MESSAGES == "n" ]; then
                    if [ `expr $END_SECOND - $LAST_CONSENSUS_SECOND` -lt 60 ]; then
                        LIVENESS_CHECK=${LIVENESS_CHECK}${ORANGE}I
                    else
                        LIVENESS_CHECK=${LIVENESS_CHECK}${RED}U
                    fi
                elif [ -n "$TERMINATED" ]; then
                    LIVENESS_CHECK=${LIVENESS_CHECK}${GREEN}O
                else
                    LIVENESS_CHECK=${LIVENESS_CHECK}${ORANGE}B
                fi
            else
                LIVENESS_CHECK=${LIVENESS_CHECK}${GREEN}-
            fi

            # Compute Safety: message are delivered only once
            #                 all server chunks should have ADELIVER messages in the same order as the corresponding reference chunk
            #                 all correct server chunks should have the same number of messages as the corresponding reference chunk
            export ALL_UNIQUE_PROCESS="y"
            if [ `grep -i deliver ${OUT_FILE} | sort | uniq -d | wc -l` -gt 0 ]; then
                ALL_UNIQUE_PROCESS="n"
            fi

            export IS_ORDERED_PROCESS="y"
            export IS_COMPLETE_PROCESS="y"
            if [ $TYPE != "C" ]; then
                export NB_CHUNKS=`ls ${TEST_TMP_PATH}/${PROCESS}.part* 2>/dev/null | wc -l`
                if [ $NB_CHUNKS -gt 0 ]; then
                    export LAST_CHUNK=${TEST_TMP_PATH}/${PROCESS}.part`expr $NB_CHUNKS - 1`
                    if [ $NB_CHUNKS -lt 11 ]; then
                        LAST_CHUNK=${TEST_TMP_PATH}/${PROCESS}.part0`expr $NB_CHUNKS - 1`
                    fi
                    for CHUNK in `ls ${TEST_TMP_PATH}/${PROCESS}.part*`; do
                        export REFERENCE_CHUNK=$(get_corresponding_chunk ${TEST_TMP_PATH} ${REFERENCE_SERVER} ${CHUNK})

                        if [ -n "$REFERENCE_CHUNK" ]; then
                            export REFERENCE_CHUNK_ADELIVER=`mktemp`
                            grep -i "ADELIVER" $REFERENCE_CHUNK > $REFERENCE_CHUNK_ADELIVER

                            export CHUNK_ADELIVER=`mktemp`
                            grep -i "ADELIVER" $CHUNK > $CHUNK_ADELIVER

                            if [ `diff $REFERENCE_CHUNK_ADELIVER $CHUNK_ADELIVER | grep -i "ADELIVER" | grep -vE "^<" | wc -l` -gt 0 ]; then
                                IS_ORDERED_PROCESS="n"
                            fi
                            rm $REFERENCE_CHUNK_ADELIVER $CHUNK_ADELIVER

                            if [ $TYPE == "S" ] || [ $TYPE == "A" ] &&
                                [ `grep -iE "$DELIVER_REGEX" $CHUNK | wc -l` -ne `grep -iE "$DELIVER_REGEX" $REFERENCE_CHUNK | wc -l` ]; then
                                if  [ $CHUNK != $LAST_CHUNK ]; then  
                                    IS_COMPLETE_PROCESS="n"
                                elif [ $IS_COMPLETE_PROCESS == "y" ]; then
                                    IS_COMPLETE_PROCESS="z"
                                fi
                            fi
                        else
                            IS_COMPLETE_PROCESS="n"
                        fi
                    done
                else
                    IS_ORDERED_PROCESS="u"
                fi
            fi
            if [ $IS_COMPLETE_PROCESS == "n" ]; then
                SAFETY_CHECK=${SAFETY_CHECK}${RED}I
            elif [ $IS_ORDERED_PROCESS == "n" ]; then
                SAFETY_CHECK=${SAFETY_CHECK}${RED}F
            elif [ $ALL_UNIQUE_PROCESS == "n" ]; then
                SAFETY_CHECK=${SAFETY_CHECK}${RED}D
            elif [ $IS_COMPLETE_PROCESS == "z" ]; then
                SAFETY_CHECK=${SAFETY_CHECK}${ORANGE}I
            elif [ $IS_COMPLETE_PROCESS == "u" ] || [ $IS_ORDERED_PROCESS == "u" ]; then
                SAFETY_CHECK=${SAFETY_CHECK}${ORANGE}-
            else
                SAFETY_CHECK=${SAFETY_CHECK}${GREEN}O
            fi 

            # Compute View : Check that the expected number of view change occurs on correct processes
            #                Check that the expected number of trusted key update occurs on correct processes
            export HAS_INSTALLED_ALL_VIEWS="u"
            export HAS_INSTALLED_ALL_KEYS="u"
            if [ $TYPE == "S" ] || [ $TYPE == "C" ]; then
                HAS_INSTALLED_ALL_VIEWS="y"
                HAS_INSTALLED_ALL_KEYS="y"

                if [ $NB_VIEW_CHANGES -ne `grep -i "view has been" $OUT_FILE | wc -l` ]; then
                    HAS_INSTALLED_ALL_VIEWS="n"
                fi
                if [ $NB_KEY_CHANGES -ne `grep -i "The trusted key has been updated !" $OUT_FILE | wc -l` ]; then
                    HAS_INSTALLED_ALL_KEYS="n"
                fi
            fi
            if [ $HAS_INSTALLED_ALL_VIEWS == "n" ]; then
                MANAGEMENT_CHECK=${MANAGEMENT_CHECK}${RED}V
            elif [ $HAS_INSTALLED_ALL_KEYS == "n" ] && [ $TYPE == "C" ]; then
                MANAGEMENT_CHECK=${MANAGEMENT_CHECK}${ORANGE}K
            elif [ $HAS_INSTALLED_ALL_KEYS == "n" ]; then
                MANAGEMENT_CHECK=${MANAGEMENT_CHECK}${RED}K
            elif [ $HAS_INSTALLED_ALL_VIEWS == "u" ] || [ $HAS_INSTALLED_ALL_KEYS == "u" ]; then
                MANAGEMENT_CHECK=${MANAGEMENT_CHECK}${GREEN}-
            else
                MANAGEMENT_CHECK=${MANAGEMENT_CHECK}${GREEN}O
            fi

            # Compute Memory
            export INTERRUPTED=`grep SIGTERM $ERR_FILE` 
            export ERRORS=`grep "ERROR SUMMARY" $ERR_FILE | grep -v "0 errors from 0 context"`
            if [ -n "$INTERRUPTED" ]; then
                MEMORY_CHECK=${MEMORY_CHECK}${ORANGE}I
            elif [ -n "$ERRORS" ]; then
                MEMORY_CHECK=${MEMORY_CHECK}${RED}E
            else
                MEMORY_CHECK=${MEMORY_CHECK}${GREEN}O
            fi
        else
            LIVENESS_CHECK=${LIVENESS_CHECK}${RED}M
            SAFETY_CHECK=${SAFETY_CHECK}${RED}M
            MANAGEMENT_CHECK=${MANAGEMENT_CHECK}${RED}M
            MEMORY_CHECK=${MEMORY_CHECK}${RED}M
        fi
    done

    # Measure algorithm efficiency 
    export NB_IGNORED_HEARDOF=`grep -E "Ignore message.*HEARD_OF" ${LOG_PATH}/*.log | wc -l`
    export NB_5_ROUND_CONSENSUS=`grep -E "The step '.*:7:0'" ${LOG_PATH}/*.log | wc -l`
    export NB_LONG_CONSENSUS=`grep -E "The step '.*:11:0'" ${LOG_PATH}/*.log | wc -l`
    export NB_ETERNAL_CONSENSUS=`grep -E "The step '.*:21:0'" ${LOG_PATH}/*.log | wc -l`

    # Display check results
    echo -n "Check test $TEST_LABEL: ${TEST_PARAMETERS[@]}                                          " | head -c 80
    echo -ne " LIV=$LIVENESS_CHECK${NC}  "
    echo -ne " SAF=$SAFETY_CHECK${NC}  "
    echo -ne " MAN=$MANAGEMENT_CHECK${NC}  "
    echo -ne " MEM=$MEMORY_CHECK${NC}    "
    echo -ne " TIM=$(format_time_number $MINIMUM_DURATION 5 $WARNING_TIME $ERROR_TIME)${NC}-$(format_time_number $MAXIMUM_DURATION 5 $WARNING_TIME $ERROR_TIME)${NC}"
    echo -ne " IHO=$(format_log_number $NB_IGNORED_HEARDOF 4 100 1000)${NC}"
    echo -ne " 5RC=$(format_log_number $NB_5_ROUND_CONSENSUS 3 50 200)${NC}"
    echo -ne " VLC=$(format_log_number $NB_LONG_CONSENSUS 3 1 10)${NC}"
    echo -e  " ELC=$(format_log_number $NB_ETERNAL_CONSENSUS 3 0 1)${NC}"
    rm -rf $LOG_PATH

    TEST_NUMBER=`expr $TEST_NUMBER + 1`
done

rm -rf $ABSOLUTE_TMP_PATH
