cmake_minimum_required(VERSION 4.0)
project(malware)

set(CMAKE_CXX_STANDARD 23)

if(DEFINED CMAKE_TOOLCHAIN_FILE)
    message(STATUS "Using Toolchain, probably vcpkg")
endif()

find_package(OpenSSL REQUIRED)
if(OpenSSL_FOUND)
    message(STATUS "OpenSSL found")
    message(STATUS "Using OpenSSL v${OpenSSL_VERSION}")
endif()
target_link_libraries(malware PRIVATE OpenSSL::SSL)
target_link_libraries(malware PRIVATE OpenSSL::Crypto)

file(GLOB CONFIGURE_DEPENDS SOURCES
        "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/*.hpp"
)
add_executable(malware ${SOURCES})
