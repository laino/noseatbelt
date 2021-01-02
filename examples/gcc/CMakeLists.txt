cmake_minimum_required(VERSION 3.5)

project (noseatbelt-example-gcc)

set(CMAKE_C_COMPILER gcc)

add_executable(example_gcc_clean ${example_SRC})
add_executable(example_gcc_thunk ${example_SRC})
add_executable(example_gcc_thunk_inline ${example_SRC})
add_executable(example_gcc_fcf ${example_SRC})

target_compile_options(example_gcc_clean PRIVATE -O3)
target_compile_options(example_gcc_thunk PRIVATE -O3 -mindirect-branch=thunk -mfunction-return=thunk)
target_compile_options(example_gcc_thunk_inline PRIVATE -O3 -mindirect-branch=thunk-inline -mfunction-return=thunk-inline)
target_compile_options(example_gcc_fcf PRIVATE -O3 -fcf-protection=full)

target_link_libraries(example_gcc_clean PRIVATE noseatbelt)
target_link_libraries(example_gcc_thunk PRIVATE noseatbelt)
target_link_libraries(example_gcc_thunk_inline PRIVATE noseatbelt)
target_link_libraries(example_gcc_fcf PRIVATE noseatbelt)

if (UNIX)
add_custom_command(TARGET example_gcc_clean POST_BUILD
    COMMAND objdump -d ${CMAKE_BINARY_DIR}/example_gcc_clean -M intel > objdump_clean.txt
    COMMENT "Running objdump (example_gcc_clean)"
)

add_custom_command(TARGET example_gcc_thunk POST_BUILD
    COMMAND objdump -d ${CMAKE_BINARY_DIR}/example_gcc_thunk -M intel > objdump_thunk.txt
    COMMENT "Running objdump (example_gcc_clean)"
)

add_custom_command(TARGET example_gcc_thunk_inline POST_BUILD
    COMMAND objdump -d ${CMAKE_BINARY_DIR}/example_gcc_thunk_inline -M intel > objdump_thunk_inline.txt
    COMMENT "Running objdump (example_gcc_clean)"
)

add_custom_command(TARGET example_gcc_fcf POST_BUILD
    COMMAND objdump -d ${CMAKE_BINARY_DIR}/example_gcc_fcf -M intel > objdump_fcf.txt
    COMMENT "Running objdump (example_gcc_clean)"
)
endif (UNIX)
