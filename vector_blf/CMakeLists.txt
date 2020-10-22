cmake_minimum_required(VERSION 3.12)

# dependencies
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

# source files
file(GLOB BLF_SOURCES "vector_blf/src/Vector/BLF/*.cpp")

# Vector_BLF do not define a static target, so we create our own
add_library(Vector_BLF STATIC ${BLF_SOURCES})
target_include_directories(Vector_BLF PUBLIC "." "vector_blf/src")
target_link_libraries(Vector_BLF zlibstatic)
target_compile_features(Vector_BLF PRIVATE cxx_std_17)
