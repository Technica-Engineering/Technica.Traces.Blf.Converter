cmake_minimum_required(VERSION 3.12)

include(FetchContent)

FetchContent_Declare(
    tinyxml2
    GIT_REPOSITORY "https://github.com/leethomason/tinyxml2.git"
    GIT_TAG "9.0.0"
)
FetchContent_MakeAvailable(tinyxml2)
