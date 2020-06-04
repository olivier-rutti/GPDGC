#!/bin/bash

if [ $# -ne 1 ]; then
    echo "Usage: $0 LOG_ARCHIVE"
    exit 1
fi

rm *.log 2>/dev/null
tar xzvf $1 --wildcards *.log > /dev/null
echo "#######################"
for LOG in *.log; do
    echo "$LOG: " `grep Propose $LOG | tail -n 1`
done
echo "#######################"
for LOG in *.log; do
    echo "$LOG: " `grep Decide  $LOG | tail -n 1`
done
echo "#######################"
for LOG in *.log; do
    echo "$LOG: " `tail -n 1 $LOG`
done
echo "#######################"
