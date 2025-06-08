cmake_minimum_required(VERSION 3.20)
project(SysCaller LANGUAGES C CXX ASM_MASM)

# Require x64 build
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "SysCaller requires 64-bit compilation.")
endif()

# Set C++ standard (change to 17, 20, or 23 as needed by your project)
set(CMAKE_CXX_STANDARD #CHANGEME)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Require MSVC for MASM (ml64.exe)
if(MSVC)
    enable_language(ASM_MASM)
else()
    message(FATAL_ERROR "SysCaller only supports MSVC (MASM required).")
endif()

# Headers and MASM source
set(HEADERS
    include/syscaller.h
    include/Sys/sysFunctions.h
    include/Sys/sysTypes.h
    include/Sys/sysExternals.h
    include/Sys/sysConstants.h
)

set(SOURCES
    src/syscaller.asm
)

# Build as static library
add_library(SysCaller STATIC ${SOURCES} ${HEADERS})

# Expose include directory
target_include_directories(SysCaller PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

# Installation rules
install(TARGETS SysCaller
    EXPORT SysCallerTargets
    ARCHIVE DESTINATION lib
)

install(DIRECTORY include/ DESTINATION include)

install(EXPORT SysCallerTargets
    FILE SysCallerConfig.cmake
    NAMESPACE SysCaller::
    DESTINATION lib/cmake/SysCaller
)