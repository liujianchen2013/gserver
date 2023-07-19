cmake_minimum_required (VERSION 3.5)
set(PROJECT_NAME ${LIBCOMMON})
project(${PROJECT_NAME})

file(GLOB_RECURSE CPP_SRC *.cpp)

add_library(${PROJECT_NAME} SHARED ${CPP_SRC})
