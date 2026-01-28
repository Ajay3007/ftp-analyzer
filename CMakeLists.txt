cmake_minimum_required(VERSION 3.10)

project(ftp_analyzer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(${CMAKE_SOURCE_DIR}/src)

# Try pkg-config first (Linux)
find_package(PkgConfig QUIET)

if (PkgConfig_FOUND)
    pkg_check_modules(PCAP QUIET libpcap)
endif()

# If pkg-config failed (macOS), fallback
if (NOT PCAP_FOUND)

    find_path(PCAP_INCLUDE_DIR
        NAMES pcap.h
    )

    find_library(PCAP_LIBRARY
        NAMES pcap
    )

    if (NOT PCAP_INCLUDE_DIR OR NOT PCAP_LIBRARY)
        message(FATAL_ERROR \"libpcap not found\")
    endif()

    set(PCAP_INCLUDE_DIRS ${PCAP_INCLUDE_DIR})
    set(PCAP_LIBRARIES ${PCAP_LIBRARY})

endif()

include_directories(${PCAP_INCLUDE_DIRS})

add_executable(ftp_analyzer
    src/main.cpp
    src/pcap_reader.cpp
    src/link_layer.cpp
    src/ftp_parser.cpp
    src/tcp_reassembly.cpp
)

target_link_libraries(ftp_analyzer
    ${PCAP_LIBRARIES}
)
