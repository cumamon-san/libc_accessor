cmake_minimum_required(VERSION 3.0)

project(tmp)

add_executable(tmp main.cpp)

install(TARGETS tmp RUNTIME DESTINATION bin)
