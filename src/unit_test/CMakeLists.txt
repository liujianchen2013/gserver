cmake_minimum_required (VERSION 3.5)
set(PROJECT_NAME "unit_test")
project(${PROJECT_NAME})

file(GLOB_RECURSE CPP_SRC *.cpp)

add_executable(${PROJECT_NAME} ${CPP_SRC})
target_link_libraries(${PROJECT_NAME} ${PROJECT_LIBS} ${VENDOR_LIBS} gtest)
