cmake_minimum_required(VERSION 3.10)

if(${CMAKE_VERSION} VERSION_LESS 3.10)
    cmake_policy(VERSION ${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION})
endif()

# project information
project(cross_testing
        VERSION 0.1
	      DESCRIPTION "libstellar-cross-testing"
        LANGUAGES C)


# guard against bad build-type strings
if (NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Debug")
endif()

include(CTest)
ENABLE_TESTING()

# specify C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED True)
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Wall -pedantic -g -O0")

set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS}")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS}")

# guard against in-source builds
if(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})
  message(FATAL_ERROR "In-source builds not allowed. Please make a new directory (called a build directory) and run CMake from there. You may need to remove CMakeCache.txt. ")
endif()

find_package(OpenSSL REQUIRED)

add_compile_definitions(TEST)
add_compile_definitions(PRINTF=)

include_directories(./libstellar/include)
include_directories($ENV{BOLOS_SDK}/lib_standard_app)

include_directories(${OPENSSL_INCLUDE_DIR})

add_executable(stellar_formatter stellar_formatter.c)

add_library(base58 SHARED $ENV{BOLOS_SDK}/lib_standard_app/base58.c)
add_library(bip32 SHARED $ENV{BOLOS_SDK}/lib_standard_app/bip32.c)
add_library(buffer SHARED $ENV{BOLOS_SDK}/lib_standard_app/buffer.c)
add_library(read SHARED $ENV{BOLOS_SDK}/lib_standard_app/read.c)
add_library(write SHARED $ENV{BOLOS_SDK}/lib_standard_app/write.c)
add_library(format SHARED $ENV{BOLOS_SDK}/lib_standard_app/format.c)
add_library(varint SHARED $ENV{BOLOS_SDK}/lib_standard_app/varint.c)
add_library(apdu_parser SHARED $ENV{BOLOS_SDK}/lib_standard_app/parser.c)
add_library(parser ./libstellar/parser.c)
add_library(printer ./libstellar/printer.c)
add_library(formatter ./libstellar/formatter.c)
add_library(base32 ./libstellar/base32.c)
add_library(base64 ./libstellar/base64.c)

target_link_libraries(stellar_formatter PUBLIC 
                      formatter
                      parser
                      printer
                      format
                      base64
                      base32
                      buffer
                      bip32
                      varint
                      write
                      read
                      bsd
                      ${OPENSSL_LIBRARIES})

add_test(stellar_formatter stellar_formatter)
