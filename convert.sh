#!/bin/bash

if [ $# -lt 1 ]; then
    echo "need dir"
    exit
fi
dir=$1

for file in $dir/*.txt
do
    mcts/conv < $file > ${file%.*}.dot # | dot -T png -o ${file%.*}.png
    dot ${file%.*}.dot -Tpng -o ${file%.*}.png
done
