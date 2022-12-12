cmake_minimum_required(VERSION 3.16.3)

project(hello)
set (CMAKE_CXX_STANDARD 20)

# zLib
find_package(ZLIB)
# Include LibElf
include(${CMAKE_CURRENT_SOURCE_DIR}/FindLibElf.cmake)
if (NOT LIBELF_FOUND)
    message(FATAL_ERROR "Unable to locate libelf")
endif(NOT LIBELF_FOUND)
add_library( libelf SHARED IMPORTED )
set_target_properties( libelf PROPERTIES IMPORTED_LOCATION ${LIBELF_LIBRARIES} )

# Build vmlinux headers (needed for .bpf.c)
add_custom_command(
  OUTPUT vmlinux.h
  COMMAND bpftool btf dump file /sys/kernel/btf/vmlinux format c > ${CMAKE_CURRENT_BINARY_DIR}/vmlinux.h
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

# Build skeleton header file for .cpp
add_custom_command(
  OUTPUT hello.skel.h
  COMMAND bpftool gen skeleton hello.bpf.o > hello.skel.h
  DEPENDS hello.bpf.o
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

# Copy bpf file to build dir
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/hello.bpf.c ${CMAKE_CURRENT_BINARY_DIR}/hello.bpf.c COPYONLY)

# Compile bpf file
add_custom_command(
  OUTPUT hello.bpf.o
  COMMAND clang -g -O2 -target bpf -D__TARGET_ARCH_x86_64 -I . -c hello.bpf.c -o hello.bpf.o
  DEPENDS hello.bpf.c
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

add_compile_options(-Wall -Wextra -pedantic)

include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})
add_executable ( ${CMAKE_PROJECT_NAME} hello.cpp vmlinux.h hello.skel.h)
target_compile_definitions(${CMAKE_PROJECT_NAME} PRIVATE DLIBCXX_ENABLE_INCOMPLETE_FEATURES=ON)

# Link Libbpf
# TODO: Make libbpf dynamic and add a real search
target_link_libraries(${CMAKE_PROJECT_NAME} ${CMAKE_CURRENT_SOURCE_DIR}/libbpf/build/libbpf/libbpf.a libelf ZLIB::ZLIB)
