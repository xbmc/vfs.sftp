project(vfs.sftp)

cmake_minimum_required(VERSION 2.6)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR})

enable_language(CXX)

find_package(Kodi REQUIRED)
find_package(p8-platform REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(SSH REQUIRED)
find_package(ZLIB REQUIRED)

include_directories(${KODI_INCLUDE_DIR}/..
                    ${p8-platform_INCLUDE_DIRS}
                    ${SSH_INCLUDE_DIRS})

set(SFTP_SOURCES src/SFTPSession.cpp
                 src/SFTPFile.cpp)

set(DEPLIBS ${p8-platform_LIBRARIES}
            ${SSH_LIBRARIES}
            ${OPENSSL_LIBRARIES}
            ${ZLIB_LIBRARIES})

add_definitions( -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64)

build_addon(vfs.sftp SFTP DEPLIBS)
