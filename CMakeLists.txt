CMAKE_MINIMUM_REQUIRED (VERSION 2.6)
PROJECT (ASN1CTEST)

include_directories(${PROJECT_SOURCE_DIR}/asn1_gen)

add_subdirectory(asn1_gen)

add_executable(asn1test_mini asn1test_mini.c)
target_link_libraries(asn1test_mini asn1gen)
