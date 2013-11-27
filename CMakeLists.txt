project(vfs.sftp)

cmake_minimum_required(VERSION 2.6)

list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR})

enable_language(CXX)

find_package(Boost REQUIRED)
find_package(xbmc REQUIRED)
find_package(xbmcplatform REQUIRED)
find_package(SSH REQUIRED)

include_directories(${XBMC_INCLUDE_DIR}
                    ${XBMCPLATFORM_INCLUDE_DIRS}
                    ${SSH_INCLUDE_DIRS})

set(SFTP_SOURCES src/SFTPSession.cpp
                 src/SFTPFile.cpp)

set(DEPLIBS ${XBMCPLATFORM_LIBRARIES}
            ${SSH_LIBRARIES})

add_definitions( -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64)

build_addon(vfs.sftp SFTP DEPLIBS)
