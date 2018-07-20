cmake_minimum_required(VERSION 2.8.12)

project(caged)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_AUTOMOC ON)

include_directories("cxxopts/include")

add_executable(${PROJECT_NAME} "main.cpp")
set_property(TARGET ${PROJECT_NAME} PROPERTY CXX_STANDARD 17)

target_link_libraries(${PROJECT_NAME})
