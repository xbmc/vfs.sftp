project(openssl)

cmake_minimum_required(VERSION 2.8)

include(ExternalProject)

if(CORE_SYSTEM_NAME MATCHES "android")
  set(configure_command CC=${CMAKE_C_COMPILER} AR=${CMAKE_AR} RANLIB=${CMAKE_RANLIB} INSTALL_PREFIX=""
                        <SOURCE_DIR>/Configure no-shared zlib
                        --install_prefix=""
                        --openssldir=${OUTPUT_DIR}
                        --with-zlib-include=${OUTPUT_DIR}/include
                        --with-zlib-lib=${OUTPUT_DIR}/lib
                        android ${CMAKE_C_FLAGS} -I${OUTPUT_DIR}/include
      && sed -ie "s|apps test||" ${PROJECT_SOURCE_DIR}/Makefile)
endif()

if(CORE_SYSTEM_NAME MATCHES "linux" OR CORE_SYSTEM_NAME MATCHES "rbpi")
  if(CMAKE_TOOLCHAIN_FILE)
    if(CPU MATCHES aarch64 OR CPU MATCHES arm64 OR CPU STREQUAL x86_64 OR ARCH MATCHES aarch64 OR ARCH STREQUAL x86_64)
      set(bitness 64)
    elseif(CPU MATCHES arm OR CPU MATCHES "i.86" OR ARCH MATCHES arm OR CPU MATCHES cortex-a7 OR CPU MATCHES arm1176jzf-s)
      set(bitness 32)
    else()
      message(WARNING "Could not detect bitness for CPU ${CPU} - assuming 32bit")
      set(bitness 32)
    endif()

    set(configure_command CC=${CMAKE_C_COMPILER} AR=${CMAKE_AR} INSTALL_PREFIX=""
                          <SOURCE_DIR>/Configure no-shared zlib
                          --install_prefix=""
                          --openssldir=${OUTPUT_DIR}
                          --with-zlib-include=${OUTPUT_DIR}/include
                          --with-zlib-lib=${OUTPUT_DIR}/lib
                          linux-generic${bitness} ${CMAKE_C_FLAGS} -I${OUTPUT_DIR}/include
        && sed -ie "s|apps test||" ${PROJECT_SOURCE_DIR}/Makefile)
  else()
    set(configure_command MACHINE=${PLATFORM} CC=${CMAKE_C_COMPILER} AR=${CMAKE_AR} <SOURCE_DIR>/config no-shared zlib
        && sed -ie "s|apps test||" ${PROJECT_SOURCE_DIR}/Makefile)
  endif()
endif()

if(CORE_SYSTEM_NAME MATCHES "ios")
  set(configure_command CC=${CMAKE_COMPILER} AR=${CMAKE_AR} INSTALL_PREFIX=""
                        <SOURCE_DIR>/Configure iphoneos-cross zlib no-asm no-krb5
                        --openssldir=${OUTPUT_DIR}
                        --install_prefix=""
      && sed -ie "s|CFLAG= |CFLAG=${CMAKE_C_FLAGS} |" ${PROJECT_SOURCE_DIR}/Makefile
      && sed -ie "s|-isysroot $.CROSS_TOP./SDKs/$.CROSS_SDK. ||" ${PROJECT_SOURCE_DIR}/Makefile
      && sed -ie "s|apps test||" ${PROJECT_SOURCE_DIR}/Makefile
      && sed -ie "s|static volatile sig_atomic_t intr_signal|static volatile intr_signal|" ${PROJECT_SOURCE_DIR}/crypto/ui/ui_openssl.c)
endif()

if(CORE_SYSTEM_NAME MATCHES "osx")
  if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(configure_command <SOURCE_DIR>/Configure darwin64-x86_64-cc zlib no-asm no-krb5 no-shared --openssldir=${OUTPUT_DIR}
        && sed -ie "s|apps test||" ${PROJECT_SOURCE_DIR}/Makefile)
  else()
    set(configure_command <SOURCE_DIR>/Configure darwin-x86-cc zlib no-asm no-krb5 no-shared --openssldir=${OUTPUT_DIR}
        && sed -ie "s|apps test||" ${PROJECT_SOURCE_DIR}/Makefile)
  endif()
endif()

externalproject_add(openssl
                    SOURCE_DIR ${CMAKE_SOURCE_DIR}
                    UPDATE_COMMAND ""
                    CONFIGURE_COMMAND ${configure_command}
                    INSTALL_COMMAND ""
                    BUILD_IN_SOURCE 1)

install(CODE "execute_process(COMMAND find ${CMAKE_SOURCE_DIR} -name Makefile -exec sed -ie s|INSTALL_PREFIX|stupidshit|g {} \;)
              execute_process(COMMAND make install_sw WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
              execute_process(COMMAND rm -f ${OUTPUT_DIR}/lib/libcrypto.so* WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
              execute_process(COMMAND rm -f ${OUTPUT_DIR}/lib/libssl.so* WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
              execute_process(COMMAND rm -f ${OUTPUT_DIR}/lib/libcrypto*dylib* WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
              execute_process(COMMAND rm -f ${OUTPUT_DIR}/lib/libssl*dylib* WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})")
