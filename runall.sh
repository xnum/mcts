#!/bin/bash

max_job=4
now=$(date "+%m-%d_%H:%M")
mkdir ${now}
cd ${now}
limit=3000

for file in ../*.py
do
    echo "======================="
    for method in DFS BFS MCTS
    do
        echo "Running - " $file $method
        while [ $(jobs | wc -l) -ge $max_job ]
        do
            clear
            top -b -n 1 -c | grep python
            echo "======================="
            sleep 5
        done
        unbuffer time python $file $method $limit > ${file##*/}_${method}.log &
        sleep 1
    done
done

wait
