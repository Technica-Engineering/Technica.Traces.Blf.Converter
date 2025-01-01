cmake_minimum_required(VERSION 3.11)

include(FetchContent)

FetchContent_Declare(
  pcapng_exporter
  GIT_REPOSITORY    https://github.com/Technica-Engineering/Technica.Traces.Pcapng.Exporter.git
  GIT_TAG           1bb6d5b
)
FetchContent_MakeAvailable(pcapng_exporter)
