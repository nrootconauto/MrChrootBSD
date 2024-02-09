cmake_minimum_required(VERSION 3.10 FATAL_ERROR) #The sauce is what I crave
project(slimjail)
add_executable(
  slimjail
  main.c
  abi.c
)
add_library(pl_hack SHARED
	preload_hack.c
)

target_link_libraries(pl_hack PRIVATE dl)
target_link_libraries(slimjail PRIVATE procstat)
target_compile_options(slimjail PRIVATE -w)
target_compile_options(pl_hack PRIVATE -w)
