cmake_minimum_required(VERSION 3.12)

project(blf_converter)

if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    if(NOT CMAKE_BUILD_TYPE)
      set(CMAKE_BUILD_TYPE Debug CACHE STRING
          "Choose the type of build, options are: None Debug Release RelWithDebInfo MinSizeRel."
          FORCE)
    endif()
endif()

# Configuration

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")
include(cmake/pcapng.cmake)
include(cmake/zlib.cmake)
include(cmake/pcapng_exporter.cmake)
include(cmake/args.cmake)
include(cmake/tinyxml2.cmake)

add_subdirectory(vector_blf)

add_executable(blf_converter "src/app.cpp" "src/channels.cpp")
target_link_libraries(blf_converter light_pcapng pcapng_exporter args tinyxml2 Vector_BLF)

install(TARGETS blf_converter COMPONENT blf_converter)

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

    list(APPEND blf_tests "binlog/test_FlexRayData")
    list(APPEND blf_tests "binlog/test_FlexRayStatusEvent")
    list(APPEND blf_tests "binlog/test_FlexRaySync")
    list(APPEND blf_tests "binlog/test_FlexRayV6Message")
    list(APPEND blf_tests "binlog/test_FlexRayV6StartCycleEvent")
    list(APPEND blf_tests "binlog/test_FlexRayVFrError")
    list(APPEND blf_tests "binlog/test_FlexRayVFrReceiveMsg")
    list(APPEND blf_tests "binlog/test_FlexRayVFrReceiveMsgEx")
    list(APPEND blf_tests "binlog/test_FlexRayVFrStartCycle")
    list(APPEND blf_tests "binlog/test_FlexRayVFrStatus")

    list(APPEND blf_tests "converter/test_CanErrorExt")
    list(APPEND blf_tests "converter/test_CanErrorFrame")
    list(APPEND blf_tests "converter/test_CanErrorFrameExt")
    list(APPEND blf_tests "converter/test_CanMessage")

    list(APPEND blf_tests "converter/test_EthernetFrame")
    list(APPEND blf_tests "converter/test_FlexRayVFrReceiveMsgEx")
    list(APPEND blf_tests "converter/test_FlexRayVFrStartCycle")
    list(APPEND blf_tests "binlog/test_LinMessage")
    list(APPEND blf_tests "binlog/test_LinMessage2")
    list(APPEND blf_tests "binlog/test_LinCrcError")
    list(APPEND blf_tests "binlog/test_LinCrcError2")
    list(APPEND blf_tests "binlog/test_LinReceiveError")
    list(APPEND blf_tests "binlog/test_LinReceiveError2")
    list(APPEND blf_tests "binlog/test_LinSendError")
    list(APPEND blf_tests "binlog/test_LinSendError2")
    list(APPEND blf_tests "binlog/test_LinSyncError")
    list(APPEND blf_tests "binlog/test_LinSyncError2")

    list(APPEND blf_mapping_tests "test_CanMessage")

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
    foreach(blf_test ${blf_mapping_tests})
        get_filename_component(param ${blf_test} NAME)
        string(REPLACE "/" "." param ${blf_test})
        add_test(
            NAME "mapping.${param}"
            COMMAND blf_converter 
                "--channel-map" "${CMAKE_CURRENT_LIST_DIR}/tests/mapping.json"
                "${CMAKE_CURRENT_LIST_DIR}/tests/input/${blf_test}.blf"
                "${CMAKE_CURRENT_LIST_DIR}/tests/results/mapping/from_${blf_test}.pcapng"
        )
    endforeach()

endif()
