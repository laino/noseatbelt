cmake_minimum_required(VERSION 3.5)

project (noseatbelt-example-msvc)

set(CMAKE_C_COMPILER msvc)

add_executable(example_msvc_spectre ../../src/example.c)
add_executable(example_msvc_clean ../../src/example.c)

target_compile_options(example_msvc_spectre PRIVATE -Qspectre)
target_compile_options(example_msvc_clean PRIVATE)