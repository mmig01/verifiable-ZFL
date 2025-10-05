#!/bin/bash

# 2. 첫 번째 인자(C++ 소스 파일)가 있는지 확인
if [ -z "$1" ]; then
    echo "error! how to use: $0 <cpp_source_file>"
    exit 1
fi

SOURCE_FILE=$1
EXECUTABLE_NAME=${SOURCE_FILE%.cpp}

MESSAGE="|| Compiling '$SOURCE_FILE' to '$EXECUTABLE_NAME' ||"

MSG_LENGTH=${#MESSAGE}

BORDER=$(printf '%*s' "$MSG_LENGTH" '' | tr ' ' '=')

echo "$BORDER"
echo "$MESSAGE"
echo "$BORDER"

g++ -std=c++17 -Wall -o "$EXECUTABLE_NAME" "$SOURCE_FILE"

if [ $? -eq 0 ]; then
    ./"$EXECUTABLE_NAME"
else
    echo "error!"
    exit 1
fi