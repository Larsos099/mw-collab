cmake_minimum_required(VERSION 4.0)
project(malware)

set(CMAKE_CXX_STANDARD 23)

if(DEFINED CMAKE_TOOLCHAIN_FILE)
    message(STATUS "Using Toolchain, probably vcpkg")
endif()

find_package(OpenSSL REQUIRED)

if(OPENSSL_FOUND)
    message(STATUS "OpenSSL found")
endif()

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} SOURCES)

message(STATUS "Sources: ${SOURCES}")

add_executable(malware ${SOURCES})

target_link_libraries(malware PRIVATE OpenSSL::SSL OpenSSL::Crypto)
