cmake_minimum_required(VERSION 3.5)

project (noseatbelt-example-clang)

set(CMAKE_C_COMPILER clang)

add_executable(example_clang ../../src/example.c)
add_executable(example_clang_clean ../../src/example.c)

target_compile_options(example_clang PRIVATE -g -O0 -mspeculative-load-hardening)
target_compile_options(example_clang_clean PRIVATE -g -O0)

if (UNIX)
add_custom_command(TARGET example_clang POST_BUILD
    COMMAND objdump -d example_clang -M intel > objdump.txt
    COMMENT "Running objdump (example_clang)"
)

add_custom_command(TARGET example_clang_clean POST_BUILD
    COMMAND objdump -d example_clang_clean -M intel > objdump_clean.txt
    COMMENT "Running objdump (example_clang_clean)"
)
endif (UNIX)
