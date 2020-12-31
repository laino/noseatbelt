cmake_minimum_required(VERSION 3.15)

project (noseatbelt)

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    message("")
    message("                      //")
    message("                     //")
    message("  Release Build   \\\\//")
    message("                   \\/")
    message("  ")
else()
    message("")
    message("  ===================")
    message("  !!! DEBUG BUILD !!!")
    message("  ===================")
    message("")
endif()

if (UNIX)
    add_compile_definitions(UNIX)
elseif (WIN32)
    add_compile_definitions(WIN32)
endif ()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set (CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set (CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

option(ZYDIS_BUILD_TOOLS "" OFF)
option(ZYDIS_BUILD_EXAMPLES "" OFF)

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    option(ZYDIS_FEATURE_FORMATTER "" OFF)
else()
    option(ZYDIS_FEATURE_FORMATTER "" ON)
endif()

option(ZYDIS_BUILD_SHARED_LIB "" ON)
add_subdirectory(dependencies/zydis)

include_directories(
    ./include
    ./dependencies/zydis/include
    ./dependencies/zydis/dependencies/zycore/include
    ${CMAKE_BINARY_DIR}/dependencies/zydis
    ${CMAKE_BINARY_DIR}/dependencies/zydis/zycore)

add_library(noseatbelt SHARED src/noseatbelt.c src/remove-all-unix.c src/remove-all-win32.c)

if (UNIX)
    target_link_libraries(noseatbelt PRIVATE Zydis) 
elseif (WIN32)
    target_link_libraries(noseatbelt PRIVATE Zydis Dbghelp) 
endif ()

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

