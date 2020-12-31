cmake_minimum_required(VERSION 3.5)

project (noseatbelt-example-clang)

set(CMAKE_C_COMPILER clang)

add_executable(example_clang_clean ../../src/example)
add_executable(example_clang_hardened ../../src/example)

target_compile_options(example_clang_clean PRIVATE)
target_compile_options(example_clang_hardened PRIVATE -mspeculative-load-hardening)

target_link_libraries(example_clang_clean PRIVATE noseatbelt)
target_link_libraries(example_clang_hardened PRIVATE noseatbelt)

if (UNIX)
add_custom_command(TARGET example_clang_clean POST_BUILD
    COMMAND objdump -d ${CMAKE_BINARY_DIR}/example_clang_clean -M intel > objdump_clean.txt
    COMMENT "Running objdump (example_clang_clean)"
)

add_custom_command(TARGET example_clang_hardened POST_BUILD
    COMMAND objdump -d ${CMAKE_BINARY_DIR}/example_clang_hardened -M intel > objdump_hardened.txt
    COMMENT "Running objdump (example_clang_hardened)"
)
endif (UNIX)
