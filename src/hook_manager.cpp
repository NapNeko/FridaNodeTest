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
#include <psapi.h>
#pragma comment(lib, "psapi.lib")
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
#include <unordered_map>

// Global state
static bool g_frida_initialized = false;
static GumInterceptor *g_interceptor = nullptr;

// Hook management: maps original address to trampoline address
static std::unordered_map<uint64_t, uint64_t> g_hook_map;

#ifdef _MSC_VER
#define NOINLINE __declspec(noinline)
#else
#define NOINLINE __attribute__((noinline))
#endif

// ============================================================================
// Core Hook Functions - Platform Independent
// ============================================================================

/**
 * Initialize Frida-gum if not already initialized
 */
static void EnsureFridaInitialized()
{
    if (!g_frida_initialized)
    {
        gum_init_embedded();
        g_frida_initialized = true;
        std::cout << "[frida] Frida-gum initialized" << std::endl;
    }
}

/**
 * Remove inline hook
 * @param oriAddr Original function address to unhook
 * @return true if successful, false otherwise
 */
static bool InlineUnhook(void *oriAddr)
{
    EnsureFridaInitialized();

    if (oriAddr == nullptr)
    {
        std::cerr << "[unhook] Error: Invalid address (oriAddr is null)" << std::endl;
        return false;
    }

    uint64_t oriAddrValue = reinterpret_cast<uint64_t>(oriAddr);
    
    // Check if hook exists
    if (g_hook_map.find(oriAddrValue) == g_hook_map.end())
    {
        std::cerr << "[unhook] Error: No hook found at address " << oriAddr << std::endl;
        return false;
    }

    std::cout << "[unhook] Removing hook at: " << oriAddr << std::endl;

    if (g_interceptor == nullptr)
    {
        std::cerr << "[unhook] Error: Interceptor not initialized" << std::endl;
        return false;
    }

    gum_interceptor_begin_transaction(g_interceptor);
    gum_interceptor_revert(g_interceptor, oriAddr);
    gum_interceptor_end_transaction(g_interceptor);

    // Remove from map
    g_hook_map.erase(oriAddrValue);

    std::cout << "[unhook] Hook removed successfully" << std::endl;
    return true;
}

/**
 * Inline hook function
 * @param oriAddr Original function address to hook
 * @param targetAddr Replacement function address
 * @return Address of the trampoline (can be used to call original function), or nullptr on failure
 */
static void *InlineHook(void *oriAddr, void *targetAddr)
{
    EnsureFridaInitialized();

    if (oriAddr == nullptr || targetAddr == nullptr)
    {
        std::cerr << "[hook] Error: Invalid address (oriAddr or targetAddr is null)" << std::endl;
        return nullptr;
    }

    std::cout << "[hook] Installing hook: " << oriAddr << " -> " << targetAddr << std::endl;

    // Validate that target memory is readable
    if (!gum_memory_is_readable(oriAddr, 16))
    {
        std::cerr << "[hook] Error: Target memory is not readable" << std::endl;
        return nullptr;
    }

    // Get or create interceptor
    if (g_interceptor == nullptr)
    {
        g_interceptor = gum_interceptor_obtain();
    }

#ifdef __APPLE__
    // On macOS, mark memory as code to allow modification
    gsize page_size = gum_query_page_size();
    gpointer page_start = GSIZE_TO_POINTER(
        GPOINTER_TO_SIZE(oriAddr) & ~(page_size - 1));

    if (!gum_memory_mark_code(page_start, page_size))
    {
        std::cout << "[hook] Warning: gum_memory_mark_code failed, continuing anyway..." << std::endl;
    }
#endif

    void *trampoline = nullptr;

    // Perform the hook operation
    gum_interceptor_begin_transaction(g_interceptor);

    GumReplaceReturn ret = gum_interceptor_replace(
        g_interceptor,
        oriAddr,
        targetAddr,
        NULL,
        &trampoline);

    gum_interceptor_end_transaction(g_interceptor);

    if (ret != GUM_REPLACE_OK)
    {
        std::cerr << "[hook] Error: Hook failed with code " << ret << std::endl;
        return nullptr;
    }

    // Store hook information
    uint64_t oriAddrValue = reinterpret_cast<uint64_t>(oriAddr);
    uint64_t trampolineValue = reinterpret_cast<uint64_t>(trampoline);
    g_hook_map[oriAddrValue] = trampolineValue;

    std::cout << "[hook] Hook installed successfully, trampoline at: " << trampoline << std::endl;
    return trampoline;
}

// ============================================================================
// Test Functions (for testing hook functionality)
// ============================================================================

extern "C"
{
    // Test function that returns 42
    NOINLINE int TestOriginalFunction()
    {
        volatile int sum = 0;
        for (volatile int i = 0; i < 8; i++)
            sum += i;
        volatile int result = 42;
        if (sum == 28)
            result += sum;
        return result;
    }

    // Replacement function that returns 99
    NOINLINE int TestReplacementFunctionImpl()
    {
        return 99;
    }

    // Wrapper to call the test function
    NOINLINE int CallTestFunction()
    {
        return TestOriginalFunction();
    }
}

/**
 * Get function address by export name
 * @param moduleName Module name
 * @param functionName Function export name
 * @return Function address, or nullptr if not found
 */
static void *GetFunctionAddressByName(const std::string &moduleName, const std::string &functionName)
{
#ifdef _WIN32
    HMODULE hModule = GetModuleHandleA(moduleName.c_str());
    if (!hModule)
        hModule = LoadLibraryA(moduleName.c_str());
    
    if (!hModule)
    {
        std::cerr << "[resolve] Error: Module not found: " << moduleName << std::endl;
        return nullptr;
    }

    void *funcAddr = reinterpret_cast<void *>(GetProcAddress(hModule, functionName.c_str()));
    if (!funcAddr)
    {
        std::cerr << "[resolve] Error: Function not found: " << functionName << " in " << moduleName << std::endl;
        return nullptr;
    }

    std::cout << "[resolve] Found function " << functionName << " at " << funcAddr << std::endl;
    return funcAddr;
#else
    void *handle = dlopen(moduleName.c_str(), RTLD_LAZY | RTLD_NOLOAD);
    if (!handle)
        handle = dlopen(moduleName.c_str(), RTLD_LAZY);
    
    if (!handle)
    {
        std::cerr << "[resolve] Error: Module not found: " << moduleName << std::endl;
        return nullptr;
    }

    void *funcAddr = dlsym(handle, functionName.c_str());
    if (!funcAddr)
    {
        std::cerr << "[resolve] Error: Function not found: " << functionName << " in " << moduleName << std::endl;
        dlclose(handle);
        return nullptr;
    }

    std::cout << "[resolve] Found function " << functionName << " at " << funcAddr << std::endl;
    // Don't close handle to keep function accessible
    return funcAddr;
#endif
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

// ============================================================================
// N-API Interface Functions
// ============================================================================

/**
 * Init(): Initialize Frida-gum
 * @returns {boolean} true if successful
 */
Napi::Value Init(const Napi::CallbackInfo &info)
{
    Napi::Env env = info.Env();
    EnsureFridaInitialized();
    return Napi::Boolean::New(env, true);
}

/**
 * GetFunctionAddressByRva(moduleName: string, rva: number|bigint): Calculate absolute address
 * @param moduleName - Name of the module
 * @param rva - Relative virtual address
 * @returns {BigInt} Absolute address
 */
Napi::Value GetFunctionAddressByRva(const Napi::CallbackInfo &info)
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

/**
 * GetFunctionAddressByName(moduleName: string, functionName: string): Get function address by name
 * @param moduleName - Name of the module
 * @param functionName - Name of the exported function
 * @returns {BigInt} Function address
 */
Napi::Value GetFunctionAddressByName(const Napi::CallbackInfo &info)
{
    Napi::Env env = info.Env();

    if (info.Length() < 2 || !info[0].IsString() || !info[1].IsString())
    {
        Napi::TypeError::New(env, "Expected (moduleName: string, functionName: string)").ThrowAsJavaScriptException();
        return env.Null();
    }

    std::string moduleName = info[0].As<Napi::String>().Utf8Value();
    std::string functionName = info[1].As<Napi::String>().Utf8Value();

    void *funcAddr = GetFunctionAddressByName(moduleName, functionName);
    if (!funcAddr)
    {
        Napi::Error::New(env, "Failed to find function").ThrowAsJavaScriptException();
        return env.Null();
    }

    uint64_t addr = reinterpret_cast<uint64_t>(funcAddr);
    return Napi::BigInt::New(env, addr);
}

/**
 * HookTest(): Test function to hook TestOriginalFunction
 * @returns {boolean} true if hook was successful
 */
Napi::Value HookTest(const Napi::CallbackInfo &info)
{
    Napi::Env env = info.Env();

    void *oriAddr = reinterpret_cast<void *>(&TestOriginalFunction);
    void *targetAddr = reinterpret_cast<void *>(&TestReplacementFunctionImpl);

    void *trampoline = InlineHook(oriAddr, targetAddr);

    if (trampoline == nullptr)
    {
        Napi::Error::New(env, "Hook test failed").ThrowAsJavaScriptException();
        return Napi::Boolean::New(env, false);
    }

    return Napi::Boolean::New(env, true);
}

/**
 * CallTestFunction(): Call the hooked test function
 * @returns {number} Result from the function call
 */
Napi::Value CallTestFunction(const Napi::CallbackInfo &info)
{
    Napi::Env env = info.Env();

    std::cout << "[test] Calling hooked test function..." << std::endl;

    int result = CallTestFunction();

    std::cout << "[test] Result: " << result << std::endl;
    return Napi::Number::New(env, result);
}

/**
 * Hook(oriAddr: BigInt, targetAddr: BigInt): Perform inline hook
 * @param oriAddr - Original function address to hook
 * @param targetAddr - Replacement function address
 * @returns {BigInt|null} Trampoline address (can be used to call original function), or null on failure
 */
Napi::Value Hook(const Napi::CallbackInfo &info)
{
    Napi::Env env = info.Env();

    // Validate parameters
    if (info.Length() < 2 || !info[0].IsBigInt() || !info[1].IsBigInt())
    {
        Napi::TypeError::New(env, "Expected (oriAddr: BigInt, targetAddr: BigInt)").ThrowAsJavaScriptException();
        return env.Null();
    }

    // Get addresses from BigInt parameters
    bool lossless = false;
    uint64_t oriAddrValue = info[0].As<Napi::BigInt>().Uint64Value(&lossless);
    uint64_t targetAddrValue = info[1].As<Napi::BigInt>().Uint64Value(&lossless);

    void *oriAddr = reinterpret_cast<void *>(oriAddrValue);
    void *targetAddr = reinterpret_cast<void *>(targetAddrValue);

    // Call core hook function
    void *trampoline = InlineHook(oriAddr, targetAddr);

    if (trampoline == nullptr)
    {
        Napi::Error::New(env, "Inline hook failed").ThrowAsJavaScriptException();
        return env.Null();
    }

    // Return trampoline address as BigInt
    uint64_t trampolineAddr = reinterpret_cast<uint64_t>(trampoline);
    return Napi::BigInt::New(env, trampolineAddr);
}

/**
 * Unhook(oriAddr: BigInt): Remove inline hook
 * @param oriAddr - Original function address to unhook
 * @returns {boolean} true if successful
 */
Napi::Value Unhook(const Napi::CallbackInfo &info)
{
    Napi::Env env = info.Env();

    if (info.Length() < 1 || !info[0].IsBigInt())
    {
        Napi::TypeError::New(env, "Expected (oriAddr: BigInt)").ThrowAsJavaScriptException();
        return Napi::Boolean::New(env, false);
    }

    bool lossless = false;
    uint64_t oriAddrValue = info[0].As<Napi::BigInt>().Uint64Value(&lossless);
    void *oriAddr = reinterpret_cast<void *>(oriAddrValue);

    bool success = InlineUnhook(oriAddr);
    if (!success)
    {
        Napi::Error::New(env, "Failed to unhook function").ThrowAsJavaScriptException();
        return Napi::Boolean::New(env, false);
    }

    return Napi::Boolean::New(env, true);
}

/**
 * CallFunctionNoArg(address: BigInt): Call a function at the given address with no arguments
 * @param address - Function address to call
 * @returns {number} Function return value (int)
 */
Napi::Value CallFunctionNoArg(const Napi::CallbackInfo &info)
{
    Napi::Env env = info.Env();

    if (info.Length() < 1 || !info[0].IsBigInt())
    {
        Napi::TypeError::New(env, "Expected (address: BigInt)").ThrowAsJavaScriptException();
        return env.Null();
    }

    bool lossless = false;
    uint64_t funcAddr = info[0].As<Napi::BigInt>().Uint64Value(&lossless);

    // Cast to function pointer with no arguments
    typedef int (*FuncType)();
    FuncType func = reinterpret_cast<FuncType>(funcAddr);

    std::cout << "[call] Calling function at: " << reinterpret_cast<void *>(funcAddr) << std::endl;

    int result = func();

    std::cout << "[call] Function returned: " << result << std::endl;

    return Napi::Number::New(env, result);
}