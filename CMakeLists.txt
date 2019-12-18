cmake_minimum_required(VERSION 3.5)
project(vfs.sftp)

list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR})

find_package(Kodi REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(SSH REQUIRED)
find_package(ZLIB REQUIRED)

include_directories(${KODI_INCLUDE_DIR}/..
                    ${SSH_INCLUDE_DIRS})

set(SFTP_SOURCES src/SFTPSession.cpp
                 src/SFTPFile.cpp)

set(SFTP_HEADERS src/SFTPSession.h)

set(DEPLIBS ${OPENSSL_LIBRARIES}
            ${SSH_LIBRARIES}
            ${ZLIB_LIBRARIES})

add_definitions( -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64)

if(CORE_SYSTEM_NAME MATCHES "windows")
  list(APPEND DEPLIBS WS2_32.lib)
  add_definitions(-D_CRT_NONSTDC_NO_DEPRECATE -DLIBSSH_STATIC)
endif()

build_addon(vfs.sftp SFTP DEPLIBS)

include(CPack)
