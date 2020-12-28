cmake_minimum_required(VERSION 3.5)

project (noseatbelt-example-gcc)

set(CMAKE_C_COMPILER gcc)

add_executable(example_gcc ../../src/example.c)
add_executable(example_gcc_clean ../../src/example.c)

target_compile_options(example_gcc PRIVATE -mindirect-branch=thunk -mindirect-branch-register -mfunction-return=thunk)
target_compile_options(example_gcc_clean PRIVATE)

if (UNIX)
add_custom_command(TARGET example_gcc POST_BUILD
    COMMAND objdump -d example_gcc -M intel > objdump.txt
    COMMENT "Running objdump (example_gcc)"
)

add_custom_command(TARGET example_gcc_clean POST_BUILD
    COMMAND objdump -d example_gcc_clean -M intel > objdump_clean.txt
    COMMENT "Running objdump (example_gcc_clean)"
)
endif (UNIX)
