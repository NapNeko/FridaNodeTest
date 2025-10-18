cmake_minimum_required(VERSION 3.15)
project(frida_hook_addon)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Include Node-API
execute_process(
    COMMAND node -p "require('node-addon-api').include"
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_VARIABLE NODE_ADDON_API_DIR
)
string(REPLACE "\n" "" NODE_ADDON_API_DIR ${NODE_ADDON_API_DIR})
string(REPLACE "\"" "" NODE_ADDON_API_DIR ${NODE_ADDON_API_DIR})

# Include cmake-js
include_directories(${CMAKE_JS_INC})

# Download and use Frida Gum DevKit
set(FRIDA_VERSION "17.4.0")

if(WIN32)
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        set(FRIDA_ARCH "x86_64")
    else()
        set(FRIDA_ARCH "x86")
    endif()
    set(FRIDA_OS "windows")
elseif(APPLE)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm64")
        set(FRIDA_ARCH "arm64")
    else()
        set(FRIDA_ARCH "x86_64")
    endif()
    set(FRIDA_OS "macos")
else()
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
        set(FRIDA_ARCH "arm64")
    else()
        set(FRIDA_ARCH "x86_64")
    endif()
    set(FRIDA_OS "linux")
endif()

set(FRIDA_DEVKIT_URL "https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-gum-devkit-${FRIDA_VERSION}-${FRIDA_OS}-${FRIDA_ARCH}.tar.xz")
set(FRIDA_DEVKIT_DIR "${CMAKE_SOURCE_DIR}/.frida-devkit")
set(FRIDA_DEVKIT_ARCHIVE "${CMAKE_SOURCE_DIR}/.frida-devkit.tar.xz")

# Download Frida DevKit if not exists
if(NOT EXISTS "${FRIDA_DEVKIT_DIR}/frida-gum.h")
    message(STATUS "Downloading Frida Gum DevKit from ${FRIDA_DEVKIT_URL}")
    file(DOWNLOAD ${FRIDA_DEVKIT_URL} "${FRIDA_DEVKIT_ARCHIVE}"
         SHOW_PROGRESS
         STATUS DOWNLOAD_STATUS)
    
    list(GET DOWNLOAD_STATUS 0 STATUS_CODE)
    if(NOT STATUS_CODE EQUAL 0)
        message(FATAL_ERROR "Failed to download Frida DevKit")
    endif()
    
    file(MAKE_DIRECTORY ${FRIDA_DEVKIT_DIR})
    execute_process(
        COMMAND ${CMAKE_COMMAND} -E tar xf "${FRIDA_DEVKIT_ARCHIVE}"
        WORKING_DIRECTORY ${FRIDA_DEVKIT_DIR}
    )
endif()

# Source files
file(GLOB SOURCE_FILES "src/*.cpp" "src/*.h")

# Create the addon
add_library(${PROJECT_NAME} SHARED ${SOURCE_FILES} ${CMAKE_JS_SRC})
set_target_properties(${PROJECT_NAME} PROPERTIES PREFIX "" SUFFIX ".node")

# Include directories
target_include_directories(${PROJECT_NAME} PRIVATE 
    ${NODE_ADDON_API_DIR}
    ${CMAKE_SOURCE_DIR}/src
    ${FRIDA_DEVKIT_DIR}
)

# Link libraries
if(WIN32)
    # Frida Gum 静态库链接（按正确顺序）
    target_link_libraries(${PROJECT_NAME} PRIVATE
        ${CMAKE_JS_LIB}
        "${FRIDA_DEVKIT_DIR}/frida-gum.lib"
        dnsapi
        iphlpapi
        ole32
        oleaut32
        psapi
        secur32
        shell32
        shlwapi
        user32
        winmm
        ws2_32
        dbghelp
        advapi32
        crypt32
        setupapi
        version
        wintrust
    )
elseif(APPLE)
    target_link_libraries(${PROJECT_NAME} 
        ${CMAKE_JS_LIB}
        ${FRIDA_DEVKIT_DIR}/libfrida-gum.a
        "-framework Foundation"
        "-framework AppKit"
        resolv
    )
    # macOS specific: disable hardened runtime for development
    # Add linker flags to allow runtime code modification
    set_target_properties(${PROJECT_NAME} PROPERTIES
        LINK_FLAGS "-Wl,-no_adhoc_codesign"
        XCODE_ATTRIBUTE_CODE_SIGN_IDENTITY ""
        XCODE_ATTRIBUTE_CODE_SIGNING_REQUIRED "NO"
        XCODE_ATTRIBUTE_CODE_SIGNING_ALLOWED "NO"
        XCODE_ATTRIBUTE_ENABLE_HARDENED_RUNTIME "NO"
    )
    
    # Add custom command to codesign with entitlements after build
    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
        COMMAND codesign --force --deep --sign - --timestamp=none --entitlements ${CMAKE_SOURCE_DIR}/entitlements.plist $<TARGET_FILE:${PROJECT_NAME}> || true
        COMMENT "Signing with entitlements for JIT and unsigned memory execution"
        VERBATIM
    )
    
    target_compile_definitions(${PROJECT_NAME} PRIVATE
        GUM_STATIC
        GLIB_STATIC_COMPILATION
        GOBJECT_STATIC_COMPILATION
        GIO_STATIC_COMPILATION
    )
else()
    target_link_libraries(${PROJECT_NAME} 
        ${CMAKE_JS_LIB}
        ${FRIDA_DEVKIT_DIR}/libfrida-gum.a
        pthread
        dl
        rt
        resolv
    )
    target_compile_definitions(${PROJECT_NAME} PRIVATE
        GUM_STATIC
        GLIB_STATIC_COMPILATION
        GOBJECT_STATIC_COMPILATION
        GIO_STATIC_COMPILATION
    )
endif()

# Definitions
target_compile_definitions(${PROJECT_NAME} PRIVATE 
    NAPI_VERSION=8
)

if(WIN32)
    target_compile_definitions(${PROJECT_NAME} PRIVATE 
        _WIN32 
        WIN32_LEAN_AND_MEAN
        GUM_STATIC
        GLIB_STATIC_COMPILATION
        GOBJECT_STATIC_COMPILATION
        GIO_STATIC_COMPILATION
    )
endif()

if(MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE /wd4251 /wd4275)
endif()
