cmake_minimum_required(VERSION 3.12)

include(FetchContent)

FetchContent_Declare(
    zlib
    GIT_REPOSITORY "https://github.com/madler/zlib.git"
    GIT_TAG "v1.2.11"
)
FetchContent_MakeAvailable(zlib)

target_include_directories(zlib PUBLIC ${zlib_BINARY_DIR} ${zlib_SOURCE_DIR})
target_include_directories(zlibstatic PUBLIC ${zlib_BINARY_DIR} ${zlib_SOURCE_DIR})
