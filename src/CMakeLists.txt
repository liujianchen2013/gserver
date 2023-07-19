cmake_minimum_required (VERSION 3.5)
project(gserver)

set(LIBCOMMON "common")
set(PROJECT_LIBS ${LIBCOMMON})
set(VENDOR_LIBS pthread glog protobuf gtest)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

include_directories(${PROJECT_SOURCE_DIR} )

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -std=c++20")

add_subdirectory(common)