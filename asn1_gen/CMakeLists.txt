file(GLOB SOURCES "*.c")
file(GLOB HEADERS "*.h")

# Uncomment to enable asn1c debug output
#set(CMAKE_C_FLAGS_DEBUG "-DEMIT_ASN_DEBUG")
add_library(asn1gen STATIC ${SOURCES} ${HEADERS})
