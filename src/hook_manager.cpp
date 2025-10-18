// Minimal, Windows-focused implementation exposing three N-API functions:
// Init, getFunctionRva, hookTest. No classes, no extra platform code.

#include <napi.h>
#include <string>
#include <cstdint>
#include <sstream>
#include <iostream>
#include <cstring>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <dlfcn.h>
#ifdef __linux__
#include <link.h>
#endif
#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif
#endif

#include "frida-gum.h"

// Global state
static bool g_frida_initialized = false;
static GumInterceptor *g_interceptor = nullptr;
static void *g_hook_target = nullptr;
static void *g_original_trampoline = nullptr; // original gateway returned by replace

#ifdef _MSC_VER
#define NOINLINE __declspec(noinline)
#else
#define NOINLINE __attribute__((noinline))
#endif

extern "C"
{
    // A tiny function we can hook for demo/testing
    // Make sure it has a proper function body that won't be optimized away
    NOINLINE int TestOriginalFunction()
    {
        // Ensure non-trivial prologue on all platforms
        volatile int sum = 0;
        for (volatile int i = 0; i < 8; i++)
            sum += i;
        // Add more instructions to ensure proper function size
        volatile int result = 42;
        if (sum == 28)
            result += sum;
        return result;
    }

    // Replacement returns 99
    NOINLINE int TestReplacementFunctionImpl()
    {
        return 99;
    }
}

// Resolve module base address across platforms
static void *GetModuleBaseAddress(const std::string &moduleName)
{
#ifdef _WIN32
    HMODULE hModule = GetModuleHandleA(moduleName.c_str());
    if (!hModule)
        hModule = LoadLibraryA(moduleName.c_str());
    return reinterpret_cast<void *>(hModule);
#elif defined(__APPLE__)
    uint32_t imageCount = _dyld_image_count();
    for (uint32_t i = 0; i < imageCount; i++)
    {
        const char *imageName = _dyld_get_image_name(i);
        if (imageName && strstr(imageName, moduleName.c_str()) != nullptr)
        {
            return const_cast<void *>(reinterpret_cast<const void *>(_dyld_get_image_header(i)));
        }
    }
    void *handle = dlopen(moduleName.c_str(), RTLD_LAZY | RTLD_NOLOAD);
    if (!handle)
        handle = dlopen(moduleName.c_str(), RTLD_LAZY);
    if (handle)
    {
        Dl_info info;
        if (dladdr(dlsym(handle, ""), &info))
        {
            dlclose(handle);
            return const_cast<void *>(info.dli_fbase);
        }
        dlclose(handle);
    }
    return nullptr;
#else
    void *handle = dlopen(moduleName.c_str(), RTLD_LAZY | RTLD_NOLOAD);
    if (!handle)
        handle = dlopen(moduleName.c_str(), RTLD_LAZY);
    if (handle)
    {
        struct link_map *map = nullptr;
        if (dlinfo(handle, RTLD_DI_LINKMAP, &map) == 0 && map)
        {
            return reinterpret_cast<void *>(map->l_addr);
        }
    }
    return nullptr;
#endif
}

// Init(): initialize Frida gum once
Napi::Value Js_Init(const Napi::CallbackInfo &info)
{
    Napi::Env env = info.Env();
    if (!g_frida_initialized)
    {
        gum_init_embedded();
        g_frida_initialized = true;
    }
    return Napi::Boolean::New(env, true);
}

// getFunctionRva(moduleName: string, rva: number) => BigInt absolute address
Napi::Value Js_getFunctionRva(const Napi::CallbackInfo &info)
{
    Napi::Env env = info.Env();
    if (info.Length() < 2 || !info[0].IsString() || (!info[1].IsNumber() && !info[1].IsBigInt()))
    {
        Napi::TypeError::New(env, "Expected (moduleName: string, rva: number|bigint)").ThrowAsJavaScriptException();
        return env.Null();
    }
    std::string moduleName = info[0].As<Napi::String>().Utf8Value();
    uint64_t rva = 0;
    if (info[1].IsBigInt())
    {
        bool lossless = false;
        rva = info[1].As<Napi::BigInt>().Uint64Value(&lossless);
        if (!lossless)
        {
            // Still accept but note potential precision loss
        }
    }
    else
    {
        rva = static_cast<uint64_t>(info[1].As<Napi::Number>().Int64Value());
    }

    void *basePtr = GetModuleBaseAddress(moduleName);
    if (!basePtr)
    {
        Napi::Error::New(env, "Failed to get module base").ThrowAsJavaScriptException();
        return env.Null();
    }
    uint64_t base = reinterpret_cast<uint64_t>(basePtr);
    uint64_t addr = base + rva;
    return Napi::BigInt::New(env, addr);
}

// hookTest(): replace TestOriginalFunction with TestReplacementFunctionImpl using Frida
Napi::Value Js_hookTest(const Napi::CallbackInfo &info)
{
    Napi::Env env = info.Env();
    if (!g_frida_initialized)
    {
        gum_init_embedded();
        g_frida_initialized = true;
    }

    g_hook_target = reinterpret_cast<void *>(&TestOriginalFunction);
    void *replacement = reinterpret_cast<void *>(&TestReplacementFunctionImpl);

    // Validate target address before hooking
    if (g_hook_target == nullptr)
    {
        Napi::Error::New(env, "Hook target is null").ThrowAsJavaScriptException();
        return Napi::Boolean::New(env, false);
    }

    std::cout << "[frida] Attempting to hook function at: " << g_hook_target << std::endl;

    // Check if memory is accessible
    if (!gum_memory_is_readable(g_hook_target, 16))
    {
        Napi::Error::New(env, "Target memory is not readable").ThrowAsJavaScriptException();
        return Napi::Boolean::New(env, false);
    }

    if (g_interceptor == nullptr)
        g_interceptor = gum_interceptor_obtain();

    // Try to make the memory writable first on macOS
#ifdef __APPLE__
    // Attempt to mark the page as writable
    gsize page_size = gum_query_page_size();
    gpointer page_start = GSIZE_TO_POINTER(
        GPOINTER_TO_SIZE(g_hook_target) & ~(page_size - 1));
    
    std::cout << "[frida] Attempting to mark memory as writable..." << std::endl;
    if (!gum_memory_mark_code_as_rwx(page_start, page_size))
    {
        std::cout << "[frida] Warning: Could not mark memory as RWX, trying anyway..." << std::endl;
    }
#endif

    // Ignore current thread to avoid potential issues
    gum_interceptor_ignore_current_thread(g_interceptor);

    // Use replace mode on all platforms
    gum_interceptor_begin_transaction(g_interceptor);
    
    GumReplaceReturn ret = gum_interceptor_replace(
        g_interceptor,
        g_hook_target,
        replacement,
        NULL,
        &g_original_trampoline);
    
    gum_interceptor_end_transaction(g_interceptor);

    // Restore thread attention
    gum_interceptor_unignore_current_thread(g_interceptor);

    if (ret != GUM_REPLACE_OK)
    {
        std::stringstream ss;
        ss << "hookTest replace failed, code=" << ret;
        Napi::Error::New(env, ss.str()).ThrowAsJavaScriptException();
        return Napi::Boolean::New(env, false);
    }
    std::cout << "[frida] replace succeeded" << std::endl;
    return Napi::Boolean::New(env, true);
}