cmake_minimum_required(VERSION 3.5)

project (noseatbelt-example-msvc)

set(CMAKE_C_COMPILER msvc)

add_executable(example_msvc_spectre ${example_SRC})
add_executable(example_msvc_clean ${example_SRC})

target_compile_options(example_msvc_spectre PRIVATE /Qspectre /guard:cf)
target_compile_options(example_msvc_clean PRIVATE)

target_link_libraries(example_msvc_spectre PRIVATE noseatbelt)
target_link_libraries(example_msvc_clean PRIVATE noseatbelt)