#!/bin/bash

if [ -z "$1" ]; then
    echo "how to use: $0 <cpp_source_file>"
    exit 1
fi

SOURCE_FILE=$1
EXECUTABLE_NAME=${SOURCE_FILE%.cpp}

OUTPUT_DIR="build/bin"

mkdir -p "$OUTPUT_DIR"

MESSAGE="|| Compiling '$SOURCE_FILE' to '$EXECUTABLE_NAME' ||"

MSG_LENGTH=${#MESSAGE}

BORDER=$(printf '%*s' "$MSG_LENGTH" '' | tr ' ' '=')

echo "$BORDER"
echo "$MESSAGE"
echo "$BORDER"

g++ -std=c++17 -Wall -o "$EXECUTABLE_NAME" "$SOURCE_FILE"

if [ $? -eq 0 ]; then
    mv "$EXECUTABLE_NAME" "$OUTPUT_DIR/"
    cd "$OUTPUT_DIR"
    
    ./"$EXECUTABLE_NAME"

    cd - > /dev/null
else
    echo "error!"
    exit 1
fi