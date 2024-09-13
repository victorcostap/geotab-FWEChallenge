cmake_minimum_required(VERSION 3.10)

#Library
project(GeotabCrypto C)

set(LIB_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src/geotab_crypto_lib")

file(GLOB SOURCES "${LIB_SOURCE_DIR}/*.c")
add_library(GeotabCrypto SHARED ${SOURCES})

target_include_directories(GeotabCrypto PUBLIC "${LIB_SOURCE_DIR}/include")

set_target_properties(GeotabCrypto PROPERTIES OUTPUT_NAME "geotab_crypto")

set_target_properties(GeotabCrypto PROPERTIES VERSION 1.0.0 SOVERSION 1)

set_target_properties(GeotabCrypto PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
)

# Copy includes to build/include
file(GLOB INCLUDES_FILES "${LIB_SOURCE_DIR}/include/*.h")
file(COPY ${INCLUDES_FILES}
     DESTINATION ${CMAKE_BINARY_DIR}/include)

#Tests Libs
project(test_geotab_crypto CXX)

set(TEST_LIB_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/test/geotab_crypto_lib")

find_package(GTest REQUIRED)

file(GLOB TEST_SOURCES "${TEST_LIB_SOURCE_DIR}/*.cpp")
add_executable(test_geotab_crypto ${TEST_SOURCES})

target_link_libraries(test_geotab_crypto ${GTEST_LIBRARIES} ${GTEST_MAIN_LIBRARIES} GeotabCrypto)

set_target_properties(test_geotab_crypto PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/test"
)

enable_testing()

add_test(NAME LibTests COMMAND test_geotab_crypto WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/test")

#CLI program
project(crypt C)

set(CLI_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src/geotab_crypto_cli")

file(GLOB CLI_SOURCES "${CLI_SOURCE_DIR}/*.c")
add_executable(crypt ${CLI_SOURCES})

target_link_libraries(crypt GeotabCrypto)

set_target_properties(crypt PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/cli"
)
