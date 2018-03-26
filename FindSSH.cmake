# - Try to find libssh
# Once done this will define
#
# SSH_FOUND - system has libssh
# SSH_INCLUDE_DIRS - the libssh include directory
# SSH_LIBRARIES - The libssh libraries

find_package(PkgConfig)
if(PKG_CONFIG_FOUND)
  pkg_check_modules(PC_SSH libssh>=0.6 QUIET)
endif()

find_path(SSH_INCLUDE_DIR NAMES libssh/libssh.h PATHS ${PC_SSH_INCLUDEDIR})
find_library(SSH_LIBRARY NAMES ssh PATHS ${PC_SSH_LIBDIR})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(SSH REQUIRED_VARS SSH_INCLUDE_DIR SSH_LIBRARY)

if(SSH_FOUND)
  set(SSH_LIBRARIES ${SSH_LIBRARY})
  set(SSH_INCLUDE_DIRS ${SSH_INCLUDE_DIR})
endif()

mark_as_advanced(SSH_INCLUDE_DIR SSH_LIBRARY)
