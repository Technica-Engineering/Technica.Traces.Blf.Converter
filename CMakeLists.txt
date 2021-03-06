cmake_minimum_required(VERSION 3.12)

project(blf_converter CXX)

if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    if(NOT CMAKE_BUILD_TYPE)
      set(CMAKE_BUILD_TYPE Debug CACHE STRING
          "Choose the type of build, options are: None Debug Release RelWithDebInfo MinSizeRel."
          FORCE)
    endif()
endif()

# Configuration

include(cmake/pcapng.cmake)
include(cmake/zlib.cmake)
add_subdirectory(vector_blf)

add_executable(blf_converter "src/app.cpp" "src/endianness.h")
target_link_libraries(blf_converter light_pcapng_static)
target_link_libraries(blf_converter Vector_BLF)

if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    # Testing
    include(CTest)
endif()

if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME AND BUILD_TESTING)
    

    list(APPEND blf_tests "binlog/test_CanErrorFrame")
    list(APPEND blf_tests "binlog/test_CanErrorFrameExt")
    list(APPEND blf_tests "binlog/test_CanFdErrorFrame64")
    list(APPEND blf_tests "binlog/test_CanFdMessage")
    list(APPEND blf_tests "binlog/test_CanFdMessage64")
    list(APPEND blf_tests "binlog/test_CanMessage")
    list(APPEND blf_tests "binlog/test_CanMessage2")

    list(APPEND blf_tests "binlog/test_EthernetFrame")
    list(APPEND blf_tests "binlog/test_EthernetFrameEx")
    list(APPEND blf_tests "binlog/test_EthernetFrameForwarded")

    list(APPEND blf_tests "converter/test_CanErrorExt")
    list(APPEND blf_tests "converter/test_CanErrorFrame")
    list(APPEND blf_tests "converter/test_CanErrorFrameExt")
    list(APPEND blf_tests "converter/test_CanMessage")

    list(APPEND blf_tests "converter/test_EthernetFrame")

    foreach(blf_test ${blf_tests})
        get_filename_component(param ${blf_test} NAME)
        string(REPLACE "/" "." param ${blf_test})
        add_test(
            NAME "convert.${param}"
            COMMAND blf_converter 
                "${CMAKE_CURRENT_LIST_DIR}/vector_blf/vector_blf/src/Vector/BLF/tests/unittests/events_from_${blf_test}.blf"
                "${CMAKE_CURRENT_LIST_DIR}/tests/results/events_from_${blf_test}.pcapng"
        )
    endforeach()

endif()
