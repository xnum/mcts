#!/bin/bash

dir=$1

for file in $dir/*.txt
do
    ./conv < $file > ${file%.*}.dot # | dot -T png -o ${file%.*}.png
    dot ${file%.*}.dot -Tpng -o ${file%.*}.png
done
