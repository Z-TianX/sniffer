cmake_minimum_required(VERSION 3.18)
project(NetSniffer LANGUAGES CXX RC)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

find_package(Qt6 6.2 REQUIRED COMPONENTS Widgets)

# ------------------------------------------------------------------
# Npcap SDK：包含 Include/ 与 Lib/ 目录
# 可通过 -DNPCAP_SDK=<路径> 或环境变量 NPCAP_SDK 指定
# ------------------------------------------------------------------
set(NPCAP_SDK "" CACHE PATH "Npcap SDK 根目录（含 Include/ 与 Lib/）")
if(NOT NPCAP_SDK)
    set(NPCAP_SDK "$ENV{NPCAP_SDK}")
endif()
if(NOT NPCAP_SDK)
    message(FATAL_ERROR "请通过 -DNPCAP_SDK=<路径> 或环境变量 NPCAP_SDK 指定 Npcap SDK 目录")
endif()

find_library(NPCAP_WPCAP_LIB   NAMES wpcap   PATHS "${NPCAP_SDK}/Lib/x64" "${NPCAP_SDK}/Lib" NO_DEFAULT_PATH REQUIRED)
find_library(NPCAP_PACKET_LIB  NAMES Packet  PATHS "${NPCAP_SDK}/Lib/x64" "${NPCAP_SDK}/Lib" NO_DEFAULT_PATH REQUIRED)

add_executable(NetSniffer WIN32
    src/main.cpp
    src/packetinfo.h
    src/packetinfo.cpp
    src/packetparser.h   src/packetparser.cpp
    src/capturethread.h  src/capturethread.cpp
    src/processmapper.h  src/processmapper.cpp
    src/tcpstreamtable.h src/tcpstreamtable.cpp
    src/streamdialog.h   src/streamdialog.cpp
    src/mainwindow.h     src/mainwindow.cpp
    app.rc
)

target_include_directories(NetSniffer PRIVATE "${NPCAP_SDK}/Include")
target_link_libraries(NetSniffer PRIVATE
    Qt6::Widgets
    ${NPCAP_WPCAP_LIB}
    ${NPCAP_PACKET_LIB}
    ws2_32 iphlpapi shell32 advapi32
)

if(MSVC)
    # 源码为 UTF-8（含中文）
    target_compile_options(NetSniffer PRIVATE /utf-8 /W3)
endif()
