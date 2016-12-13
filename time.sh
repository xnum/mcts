#!/bin/bash

# DIR=12-02_21:24; ./time.sh $DIR | tee $DIR/timeinfo.txt

if [ $# -lt 1 ]; then
    echo "need dir"
    exit
fi

dir=$1

grep -rin "elapsed" $dir/*.log | awk '{split($1,arr,":");printf ("%s %8s\n",substr(arr[2],4),substr($3,0,index($3,"elapsed")-1)) }' | awk '{ split($2,arr,":"); printf ("%-30s%g\n",$1,arr[1]*60+arr[2]) }' 

