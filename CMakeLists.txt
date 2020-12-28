cmake_minimum_required(VERSION 3.15)

set(CMAKE_C_COMPILER gcc)

project (noseatbelt)

option(ZYDIS_BUILD_TOOLS "" OFF)
option(ZYDIS_BUILD_EXAMPLES "" OFF)
option(ZYDIS_BUILD_SHARED_LIB "" ON)
add_subdirectory(dependencies/zydis)

include_directories(PRIVATE dependencies/zydis/include
                            dependencies/zydis/dependencies/zycore/include
                            ${CMAKE_BINARY_DIR}/dependencies/zydis
                            ${CMAKE_BINARY_DIR}/dependencies/zydis/zycore)


add_library(noseatbelt SHARED src/noseatbelt.c)
target_link_libraries(noseatbelt PRIVATE Zydis)

if (UNIX)
add_library(preload SHARED src/preload.c)
target_link_libraries(preload Zydis dl)
set_property(TARGET preload PROPERTY POSITION_INDEPENDENT_CODE ON)
endif (UNIX)

add_subdirectory(examples/gcc)
add_subdirectory(examples/clang)
