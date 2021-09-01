cmake_minimum_required(VERSION 3.11)

include(FetchContent)

FetchContent_Declare(
  pcapng
  GIT_REPOSITORY    https://github.com/Technica-Engineering/LightPcapNg.git
  GIT_TAG           3c848a6
)
FetchContent_MakeAvailable(pcapng)
