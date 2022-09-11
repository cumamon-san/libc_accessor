cmake_minimum_required(VERSION 3.0)

project(libc_accessor)

add_executable(main main.cpp)

install(TARGETS main RUNTIME DESTINATION bin)
