cmake_minimum_required(VERSION 3.17)
project(wildcat_net)

set(CMAKE_CXX_STANDARD 20)

set(LIB_NAME wildcat_net)

include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
conan_basic_setup()

add_library(wildcat_net library.cpp library.h include/wildcat/net/address.hpp include/wildcat/net/error.hpp include/wildcat/net/socket_stream.hpp)

include_directories("${CMAKE_CURRENT_SOURCE_DIR}/include")

# define include directories for the library
target_include_directories( "${LIB_NAME}"
        PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
        PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        )

target_link_libraries(${LIB_NAME} INTERFACE ${CONAN_LIBS})

# Set linker language property to CXX
set_target_properties(${LIB_NAME} PROPERTIES LINKER_LANGUAGE CXX)

enable_testing()
add_subdirectory(test)

add_subdirectory(example)
