cmake_minimum_required(VERSION 3.15)

set(CMAKE_EXPORT_COMPILE_COMMANDS 1)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_CXX_FLAGS "-Wall -Wextra")
set(CMAKE_CXX_FLAGS_DEBUG "-g")
set(CMAKE_CXX_FLAGS_RELEASE "-O3")

project (noseatbelt)

option(ZYDIS_BUILD_TOOLS "" OFF)
option(ZYDIS_BUILD_EXAMPLES "" OFF)
option(ZYDIS_BUILD_SHARED_LIB "" ON)
add_subdirectory(dependencies/zydis)

include_directories(
    include
    dependencies/zydis/include
    dependencies/zydis/dependencies/zycore/include
    ${CMAKE_BINARY_DIR}/dependencies/zydis
    ${CMAKE_BINARY_DIR}/dependencies/zydis/zycore)


add_library(noseatbelt SHARED src/noseatbelt.c)
target_link_libraries(noseatbelt PRIVATE Zydis)

if (UNIX)
add_library(noseatbelt-auto SHARED src/preload.c)
target_link_libraries(noseatbelt-auto Zydis dl)
set_property(TARGET noseatbelt-auto PROPERTY POSITION_INDEPENDENT_CODE ON)
endif (UNIX)

add_subdirectory(examples/gcc)
add_subdirectory(examples/clang)
