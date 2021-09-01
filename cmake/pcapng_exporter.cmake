cmake_minimum_required(VERSION 3.11)

include(FetchContent)

FetchContent_Declare(
  pcapng_exporter
  GIT_REPOSITORY    https://github.com/Technica-Engineering/Technica.Traces.Pcapng.Exporter.git
  GIT_TAG           e1e56f4
)

FetchContent_MakeAvailable(pcapng_exporter)
