#!/bin/bash
COMMAND=`g++ main.cpp -o main -Os -Wall -Wno-deprecated -lcryptopp -std=c++20 -fsanitize=address`
echo "Compiling..."
echo $COMMAND
echo "Compiled!"