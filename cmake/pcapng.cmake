cmake_minimum_required(VERSION 3.11)

include(FetchContent)

FetchContent_Declare(
  pcapng
  GIT_REPOSITORY    https://github.com/Technica-Engineering/LightPcapNg.git
  GIT_TAG           68a8bef
)
FetchContent_MakeAvailable(pcapng)
