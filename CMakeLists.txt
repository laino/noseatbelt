cmake_minimum_required(VERSION 3.5)

project (noseatbelt)

find_library(ZYDIS Zydis)

add_executable(test src/test.c)
add_executable(noseatbelt src/noseatbelt.c)

target_compile_options(test PRIVATE -mindirect-branch=thunk -mindirect-branch-register)
target_compile_options(noseatbelt PRIVATE -mindirect-branch=thunk -mindirect-branch-register)

target_link_libraries(noseatbelt ${ZYDIS})
