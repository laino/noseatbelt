cmake_minimum_required(VERSION 3.15)

set(CMAKE_EXPORT_COMPILE_COMMANDS 1)

project (noseatbelt)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

set (CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set (CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

set(CMAKE_CXX_FLAGS "-Wall -Wextra")
set(CMAKE_CXX_FLAGS_DEBUG "-g")
set(CMAKE_CXX_FLAGS_RELEASE "-O3")

option(ZYDIS_BUILD_TOOLS "" OFF)
option(ZYDIS_BUILD_EXAMPLES "" OFF)
option(ZYDIS_FEATURE_FORMATTER "" OFF)
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
target_link_libraries(noseatbelt-auto PRIVATE noseatbelt Zydis dl)
set_property(TARGET noseatbelt-auto PROPERTY POSITION_INDEPENDENT_CODE ON)
endif (UNIX)

# On Windows we only use the current compiler

if (UNIX)
    add_subdirectory(examples/gcc)
    add_subdirectory(examples/clang)
else()
    if (CMAKE_C_COMPILER_ID MATCHES "Clang")
    add_subdirectory(examples/clang)
    endif()
    if (CMAKE_C_COMPILER_ID MATCHES "GNU")
    add_subdirectory(examples/gcc)
    endif()
    if (CMAKE_C_COMPILER_ID MATCHES "MSVC")
    add_subdirectory(examples/msvc)
    endif()
endif ()

