cmake_minimum_required(VERSION 3.10 FATAL_ERROR) #The sauce is what I crave
project(mrchroot)
add_executable(
  mrchroot
  main.c
  abi.c
)
add_library(pl_hack SHARED
	preload_hack.c
)

target_link_libraries(pl_hack PRIVATE dl)
target_link_libraries(mrchroot PRIVATE procstat)
target_compile_options(mrchroot PRIVATE -w)
target_compile_options(pl_hack PRIVATE -w)
