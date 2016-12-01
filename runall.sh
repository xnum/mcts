#!/bin/bash

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
        unbuffer time python $file $method $limit | tee ${file##*/}_${method}.log & 
    done
    wait
done
