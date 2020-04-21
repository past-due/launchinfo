cmake_minimum_required (VERSION 3.5)
project (launchinfo CXX)

file(GLOB HEADERS "include/LaunchInfo.h")
set(SRC "src/LaunchInfo.cpp")

add_library(launchinfo STATIC ${HEADERS} ${SRC})
target_include_directories(launchinfo PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
