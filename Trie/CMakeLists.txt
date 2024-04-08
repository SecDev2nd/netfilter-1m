# 최소한의 CMake 버전 요구
cmake_minimum_required(VERSION 3.10)

# 프로젝트 이름 설정
project(1m-block)

# 모든 소스 파일을 소스 변수에 추가
set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/netfilter-1m.cpp
)
# 디버그 옵션 추가
set(CMAKE_BUILD_TYPE Debug)
# 실행 파일 생성
add_executable(${PROJECT_NAME} ${SOURCES})

# 라이브러리 링크
target_link_libraries(${PROJECT_NAME} netfilter_queue)
