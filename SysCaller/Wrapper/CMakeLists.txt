cmake_minimum_required(VERSION 3.20)
project(SysCaller VERSION 1.3.0 LANGUAGES C CXX ASM_MASM)

# require x64 build
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "SysCaller requires 64-bit compilation.")
endif()

# set C++ standard (change to 17, 20, or 23 as needed by your project)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# require MSVC for MASM (ml64.exe)
if(NOT MSVC)
    message(FATAL_ERROR "SysCaller only supports MSVC (MASM required).")
endif()

enable_language(ASM_MASM)

set(SYSCALLER_BUILD_MODE "DIRECT" CACHE STRING "SysCaller build mode")
set_property(CACHE SYSCALLER_BUILD_MODE PROPERTY STRINGS "DIRECT" "INDIRECT" "INLINE")

option(SYSCALLER_BINDINGS "Build with multi-language bindings support" OFF)

option(BUILD_SHARED_LIBS "Build as shared library (DLL)" OFF)

if(SYSCALLER_BUILD_MODE STREQUAL "DIRECT")
    set(SYSCALLER_MODE_DEFINE "SYSCALLER_DIRECT")
    message(STATUS "[SysCaller] Build Mode: DIRECT syscalls")
elseif(SYSCALLER_BUILD_MODE STREQUAL "INDIRECT")
    set(SYSCALLER_MODE_DEFINE "SYSCALLER_INDIRECT")
    message(STATUS "[SysCaller] Build Mode: INDIRECT syscalls (runtime resolver)")
elseif(SYSCALLER_BUILD_MODE STREQUAL "INLINE")
    set(SYSCALLER_MODE_DEFINE "SYSCALLER_INLINE")
    message(STATUS "[SysCaller] Build Mode: INLINE ASM syscalls")
else()
    message(FATAL_ERROR "Invalid SYSCALLER_BUILD_MODE. Must be DIRECT, INDIRECT, or INLINE")
endif()

if(SYSCALLER_BINDINGS)
    message(STATUS "[SysCaller] Bindings: ENABLED (DLL exports available)")
endif()

set(CORE_HEADERS
    include/syscaller.h
    include/syscaller_config.h
    include/Sys/sysFunctions.h
    include/Sys/sysTypes.h
    include/Sys/sysExternals.h
    include/Sys/sysConstants.h
)

set(CORE_SOURCES
    src/syscaller.asm
    src/build_info.cpp
)

if(SYSCALLER_BUILD_MODE STREQUAL "INDIRECT")
    list(APPEND CORE_HEADERS include/Resolver/Resolver.h)
    list(APPEND CORE_SOURCES src/Resolver/Resolver.cpp)
    message(STATUS "[SysCaller] Resolver: INCLUDED (indirect mode requires resolver)")
else()
    message(STATUS "[SysCaller] Resolver: SKIPPED (not required for ${SYSCALLER_BUILD_MODE})")
endif()

if(SYSCALLER_BINDINGS)
    list(APPEND CORE_SOURCES src/DLL/dllmain.cpp)
    message(STATUS "[SysCaller] DLL Main: INCLUDED (bindings mode)")
else()
    message(STATUS "[SysCaller] DLL Main: SKIPPED (bindings not enabled)")
endif()

if(BUILD_SHARED_LIBS)
    add_library(SysCaller SHARED ${CORE_SOURCES} ${CORE_HEADERS})
    message(STATUS "[SysCaller] Output: SHARED LIBRARY (DLL)")
else()
    add_library(SysCaller STATIC ${CORE_SOURCES} ${CORE_HEADERS})
    message(STATUS "[SysCaller] Output: STATIC LIBRARY")
endif()

target_compile_definitions(SysCaller PRIVATE
    ${SYSCALLER_MODE_DEFINE}
    $<$<BOOL:${SYSCALLER_BINDINGS}>:SYSCALLER_BINDINGS>
)

target_include_directories(SysCaller PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

if(WIN32)
    target_link_libraries(SysCaller PRIVATE
        ws2_32
        winhttp
        ntdll
    )

    if(SYSCALLER_BINDINGS)
        target_sources(SysCaller PRIVATE SysCaller.def)
        set_target_properties(SysCaller PROPERTIES
            LINK_FLAGS "/DEF:${CMAKE_CURRENT_SOURCE_DIR}/SysCaller.def"
        )
    endif()
endif()

# install library
install(TARGETS SysCaller
    EXPORT SysCallerTargets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)

# install headers
install(DIRECTORY include/ DESTINATION include)

# install CMake config
install(EXPORT SysCallerTargets
    FILE SysCallerConfig.cmake
    NAMESPACE SysCaller::
    DESTINATION lib/cmake/SysCaller
)

message(STATUS "============================================================")
message(STATUS "SysCaller v${PROJECT_VERSION} Configuration Summary")
message(STATUS "============================================================")
message(STATUS "Build Mode:     ${SYSCALLER_BUILD_MODE}")
message(STATUS "Bindings:       ${SYSCALLER_BINDINGS}")
if(SYSCALLER_BINDINGS)
    message(STATUS "Bindings Mode:  Exports enabled (.def file used)")
endif()
message(STATUS "Output Type:    ${BUILD_SHARED_LIBS}")
message(STATUS "C++ Standard:   ${CMAKE_CXX_STANDARD}")
message(STATUS "============================================================")
