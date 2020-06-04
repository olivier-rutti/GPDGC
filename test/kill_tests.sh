#!/bin/bash

for process in `ps -ef | grep gpdgc_instance_test | grep -v grep | grep -v vim | grep -v $0 | awk -F" "  '{ print $2 }'`; do
    echo "Kill $process"
    kill -KILL $process 2>/dev/null
done
