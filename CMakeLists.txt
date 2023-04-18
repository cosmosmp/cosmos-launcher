cmake_minimum_required(VERSION 3.23)
project(cosmos-launcher)

set(CMAKE_CXX_STANDARD 20)

set(SOURCES
	src/main.cc
)

add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/utf-8>")

add_executable(${PROJECT_NAME} ${SOURCES})
target_include_directories(${PROJECT_NAME} PUBLIC include)
target_link_libraries(${PROJECT_NAME} Ws2_32.lib)