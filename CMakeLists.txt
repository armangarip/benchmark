cmake_minimum_required(VERSION 2.8)
project(benchmark)

message(STATUS ${llvm_libs})

find_package(LLVM 3.5.0 REQUIRED CONFIG)

include_directories(${LLVM_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})


set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -fno-rtti -std=c++11" )

set(dir ${CMAKE_CURRENT_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${dir}")


add_executable(lli-benchmark lli-main.cpp)
add_executable(llc-benchmark llc-main.cpp)

llvm_map_components_to_libnames(llvm_libs all)

target_link_libraries(lli-benchmark ${llvm_libs})
target_link_libraries(llc-benchmark ${llvm_libs})

