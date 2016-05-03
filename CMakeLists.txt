cmake_minimum_required(VERSION 3.3)
project(benchmark2)

message(STATUS ${llvm_libs})

find_package(LLVM REQUIRED CONFIG)

include_directories(${LLVM_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})


set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -fno-rtti -std=c++11" )

set(dir ${CMAKE_CURRENT_SOURCE_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${dir}")


set(SOURCE_FILES main.cpp)
add_executable(benchmark2 ${SOURCE_FILES})

llvm_map_components_to_libnames(llvm_libs all)

target_link_libraries(benchmark2 ${llvm_libs})

