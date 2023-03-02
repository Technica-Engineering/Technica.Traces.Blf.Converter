cmake_minimum_required(VERSION 3.11)

include(FetchContent)

FetchContent_Declare(
  args
  GIT_REPOSITORY    https://github.com/Taywee/args.git
  GIT_TAG           6.4.6
  CMAKE_CACHE_ARGS  "-DARGS_MAIN_PROJECT:BOOL=OFF"
)

FetchContent_MakeAvailable(args)
