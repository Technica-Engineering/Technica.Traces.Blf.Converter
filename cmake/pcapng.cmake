cmake_minimum_required(VERSION 3.11)

include(FetchContent)

FetchContent_Declare(
  pcapng
  GIT_REPOSITORY    https://git.ad.technica-engineering.de/akaanich/LightPcapNg.git
  GIT_TAG           31df9668
)

FetchContent_MakeAvailable(pcapng)

include_directories(${pcapng_SOURCE_DIR}/include)
