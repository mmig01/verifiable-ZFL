#!/bin/bash

# 인자가 없는 경우 사용법 출력
if [ -z "$1" ]; then
    echo "============================================================"
    echo " HOW TO USE: $0 <cpp_source_file> [linker_flags...]"
    echo " EXAMPLE (default): $0 my_program.cpp"
    echo " EXAMPLE (with libs): $0 secure_noise.cpp -lssl -lcrypto"
    echo "============================================================"
    exit 1
fi

# 변수 설정
SOURCE_FILE=$1
EXECUTABLE_NAME=${SOURCE_FILE%.cpp}
LINKER_FLAGS="${@:2}" # 두 번째부터 모든 인자를 링커 플래그로 저장
OUTPUT_DIR="build/bin"

# 빌드 디렉토리 생성
mkdir -p "$OUTPUT_DIR"

# 컴파일 메시지 출력
MESSAGE="|| Compiling '$SOURCE_FILE' to '$OUTPUT_DIR/$EXECUTABLE_NAME' ||"
MSG_LENGTH=${#MESSAGE}
BORDER=$(printf '%*s' "$MSG_LENGTH" '' | tr ' ' '=')

echo "$BORDER"
echo "$MESSAGE"
echo "|| Linker Flags: '$LINKER_FLAGS' ||"
echo "$BORDER"

# 컴파일 실행 (핵심 수정 부분)
g++ -std=c++17 -Wall -O3 -o "$EXECUTABLE_NAME" "$SOURCE_FILE" $LINKER_FLAGS

# 컴파일 성공/실패 처리
if [ $? -eq 0 ]; then
    echo "|| Compile Succeeded. Moving and Running... ||"
    mv "$EXECUTABLE_NAME" "$OUTPUT_DIR/"
    cd "$OUTPUT_DIR"
    
    ./"$EXECUTABLE_NAME"

    # 원래 디렉토리로 복귀
    cd - > /dev/null
else
    echo ">> COMPILE FAILED! <<"
    exit 1
fi