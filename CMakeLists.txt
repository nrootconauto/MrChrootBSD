cmake_minimum_required(VERSION 3.10 FATAL_ERROR) #The sauce is what I crave
project(mrchroot
  LANGUAGES C)
add_executable(${PROJECT_NAME}
  main.c
  ptrace.c ptrace.h
  abi.c abi.h
  fd_cache.c fd_cache.h
  hash.c hash.h)
add_library(pl_hack SHARED
  preload_hack.c)
set_target_properties(${PROJECT_NAME} pl_hack
  PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED YES
    C_EXTENSIONS YES
    C_VISIBILITY_PRESET hidden)

target_link_libraries(pl_hack PRIVATE dl)
target_link_libraries(mrchroot PRIVATE procstat)

set(FLAGS -w -fno-stack-protector -fno-strict-aliasing)
target_compile_options(mrchroot PRIVATE ${FLAGS})
target_compile_options(pl_hack PRIVATE ${FLAGS})
