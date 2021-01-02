cmake_minimum_required(VERSION 3.15)

project (noseatbelt-example-clang)

set(CMAKE_C_COMPILER clang)

add_executable(example_clang_clean ${example_SRC})
add_executable(example_clang_hardened ${example_SRC})

target_compile_options(example_clang_clean PRIVATE -O3)
target_compile_options(example_clang_hardened PRIVATE -O3 -mspeculative-load-hardening -fvisibility=hidden -flto -fsanitize=cfi)

target_link_options(example_clang_hardened PRIVATE -flto)

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
