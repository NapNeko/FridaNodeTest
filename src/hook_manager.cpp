#include "hook_manager.h"
#include <iostream>
#include <sstream>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#pragma comment(lib, "psapi.lib")
// 链接 Frida Gum 需要的所有系统库
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "winmm.lib")
#else
#include <dlfcn.h>
#ifdef __linux__
#include <link.h>
#endif
#endif

Napi::FunctionReference HookManager::constructor;

// 自定义监听器类型（用于非 Windows 平台）
#ifndef _WIN32

// 监听器回调函数
static void test_listener_on_enter(GumInvocationListener* listener, GumInvocationContext* context) {
    // 不做任何处理
}

static void test_listener_on_leave(GumInvocationListener* listener, GumInvocationContext* context) {
    // 调试：打印进入/退出与返回值，并修改返回值为 99
    gpointer old_ret = gum_invocation_context_get_return_value(context);
    std::cout << "[frida] on_leave: old_ret=" << old_ret << std::endl;
    // 使用 GUINT_TO_POINTER 将 int 映射为 gpointer
    gum_invocation_context_replace_return_value(context, GUINT_TO_POINTER(99));
    gpointer new_ret = gum_invocation_context_get_return_value(context);
    std::cout << "[frida] on_leave: new_ret=" << new_ret << std::endl;
}

// 简单的监听器结构体
typedef struct {
    GObject parent;
} TestListener;

typedef struct {
    GObjectClass parent_class;
} TestListenerClass;

static void test_listener_iface_init(gpointer g_iface, gpointer iface_data) {
    GumInvocationListenerInterface* iface = (GumInvocationListenerInterface*)g_iface;
    iface->on_enter = test_listener_on_enter;
    iface->on_leave = test_listener_on_leave;
}

G_DEFINE_TYPE_EXTENDED(
    TestListener,
    test_listener,
    G_TYPE_OBJECT,
    0,
    G_IMPLEMENT_INTERFACE(GUM_TYPE_INVOCATION_LISTENER, test_listener_iface_init)
)

static void test_listener_class_init(TestListenerClass* klass) {
}

static void test_listener_init(TestListener* self) {
}

#define TEST_TYPE_LISTENER (test_listener_get_type())

#endif

// 测试用的内置函数实现
#ifdef _MSC_VER
#define NOINLINE __declspec(noinline)
#else
#define NOINLINE __attribute__((noinline))
#endif

extern "C" {
    NOINLINE int TestOriginalFunction() {
        return 42;  // 原始函数返回 42
    }
    
    NOINLINE int TestReplacementFunction() {
        return 99;  // 替换函数返回 99
    }
}

Napi::Object HookManager::Init(Napi::Env env, Napi::Object exports) {
    Napi::HandleScope scope(env);

    Napi::Function func = DefineClass(env, "HookManager", {
        InstanceMethod("initializeFrida", &HookManager::InitializeFrida),
        InstanceMethod("hookFunction", &HookManager::HookFunction),
        InstanceMethod("unhookFunction", &HookManager::UnhookFunction),
        InstanceMethod("getModuleBase", &HookManager::GetModuleBase),
        InstanceMethod("getFunctionAddress", &HookManager::GetFunctionAddress),
        InstanceMethod("callTestFunction", &HookManager::CallTestFunction),
        InstanceMethod("hookTestFunction", &HookManager::HookTestFunction),
    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    exports.Set("HookManager", func);
    return exports;
}

HookManager::HookManager(const Napi::CallbackInfo& info) 
    : Napi::ObjectWrap<HookManager>(info), fridaInitialized_(false) {
}

HookManager::~HookManager() {
    // 清理所有 hooks
    for (auto& pair : hooks_) {
        if (pair.second && pair.second->interceptor) {
            if (pair.second->listener) {
                // attach 模式
                gum_interceptor_detach(pair.second->interceptor, pair.second->listener);
                g_object_unref(pair.second->listener);
            } else {
                // replace 模式
                gum_interceptor_revert(pair.second->interceptor, pair.second->targetFunc);
            }
            g_object_unref(pair.second->interceptor);
        }
    }
    hooks_.clear();
    
    if (fridaInitialized_) {
        gum_deinit_embedded();
    }
}

Napi::Value HookManager::InitializeFrida(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    if (!fridaInitialized_) {
        gum_init_embedded();
        fridaInitialized_ = true;
    }
    
    return Napi::Boolean::New(env, true);
}

Napi::Value HookManager::CallTestFunction(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    // 调用测试函数并返回结果
    int result = TestOriginalFunction();
    return Napi::Number::New(env, result);
}

// 简单的替换函数：直接返回 99
extern "C" NOINLINE int TestReplacementFunctionImpl() {
    return 99;
}

Napi::Value HookManager::HookTestFunction(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    if (!fridaInitialized_) {
        Napi::Error::New(env, "Frida not initialized").ThrowAsJavaScriptException();
        return Napi::Boolean::New(env, false);
    }
    
    // 获取测试函数地址
    void* targetFunc = (void*)&TestOriginalFunction;
    
    // 调试信息：输出函数地址
    std::cout << "Target function address: " << targetFunc << std::endl;
    
    // 创建 hook 信息
    auto hookInfo = std::make_shared<HookInfo>();
    hookInfo->targetFunc = targetFunc;
    hookInfo->moduleName = "internal";
    hookInfo->rva = 0;
    
    // 创建拦截器
    hookInfo->interceptor = gum_interceptor_obtain();
    
#ifdef _WIN32
    // Windows: 使用 replace 模式（直接替换函数）
    void* replacementFunc = (void*)&TestReplacementFunctionImpl;
    std::cout << "Replacement function address: " << replacementFunc << std::endl;
    
    GumReplaceReturn ret = gum_interceptor_replace(
        hookInfo->interceptor,
        targetFunc,
        replacementFunc,
        NULL,
        NULL);
    
    if (ret != GUM_REPLACE_OK) {
        g_object_unref(hookInfo->interceptor);
        std::stringstream ss;
        ss << "Failed to hook test function, error code: " << ret;
        Napi::Error::New(env, ss.str()).ThrowAsJavaScriptException();
        return Napi::Boolean::New(env, false);
    }
    
    hookInfo->listener = NULL;
#else
    // macOS/Linux: 使用 attach 模式配合监听器修改返回值
    hookInfo->listener = GUM_INVOCATION_LISTENER(g_object_new(TEST_TYPE_LISTENER, NULL));
    
    gum_interceptor_begin_transaction(hookInfo->interceptor);
    GumAttachReturn ret = gum_interceptor_attach(
        hookInfo->interceptor,
        targetFunc,
        hookInfo->listener,
        NULL);
    gum_interceptor_end_transaction(hookInfo->interceptor);
    
    if (ret != GUM_ATTACH_OK) {
        g_object_unref(hookInfo->listener);
        g_object_unref(hookInfo->interceptor);
        std::stringstream ss;
        ss << "Failed to hook test function, error code: " << ret;
        Napi::Error::New(env, ss.str()).ThrowAsJavaScriptException();
        return Napi::Boolean::New(env, false);
    }
    
    std::cout << "Hook attached successfully on macOS/Linux" << std::endl;
#endif
    
    // 保存 hook 信息
    hooks_["test-function"] = hookInfo;
    
    return Napi::Boolean::New(env, true);
}

void* HookManager::GetModuleBaseAddress(const std::string& moduleName) {
#ifdef _WIN32
    HMODULE hModule = GetModuleHandleA(moduleName.c_str());
    if (!hModule) {
        hModule = LoadLibraryA(moduleName.c_str());
    }
    return reinterpret_cast<void*>(hModule);
#elif defined(__APPLE__)
    // macOS: 遍历所有加载的镜像
    uint32_t imageCount = _dyld_image_count();
    for (uint32_t i = 0; i < imageCount; i++) {
        const char* imageName = _dyld_get_image_name(i);
        if (imageName && strstr(imageName, moduleName.c_str()) != nullptr) {
            return const_cast<void*>(reinterpret_cast<const void*>(_dyld_get_image_header(i)));
        }
    }
    
    // 尝试通过 dlopen 加载
    void* handle = dlopen(moduleName.c_str(), RTLD_LAZY | RTLD_NOLOAD);
    if (!handle) {
        handle = dlopen(moduleName.c_str(), RTLD_LAZY);
    }
    
    if (handle) {
        // 在 macOS 上,dlsym 可以获取模块基址
        Dl_info info;
        if (dladdr(dlsym(handle, ""), &info)) {
            dlclose(handle);
            return const_cast<void*>(info.dli_fbase);
        }
        dlclose(handle);
    }
    
    return nullptr;
#else
    // Linux
    void* handle = dlopen(moduleName.c_str(), RTLD_LAZY | RTLD_NOLOAD);
    if (!handle) {
        handle = dlopen(moduleName.c_str(), RTLD_LAZY);
    }
    
    if (handle) {
        struct link_map* map;
        dlinfo(handle, RTLD_DI_LINKMAP, &map);
        if (map) {
            return reinterpret_cast<void*>(map->l_addr);
        }
    }
    return nullptr;
#endif
}

void* HookManager::GetFunctionAddressByRVA(const std::string& moduleName, size_t rva) {
    void* baseAddress = GetModuleBaseAddress(moduleName);
    if (!baseAddress) {
        return nullptr;
    }
    
    return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(baseAddress) + rva);
}

Napi::Value HookManager::GetModuleBase(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    if (info.Length() < 1 || !info[0].IsString()) {
        Napi::TypeError::New(env, "Module name expected").ThrowAsJavaScriptException();
        return env.Null();
    }
    
    std::string moduleName = info[0].As<Napi::String>().Utf8Value();
    void* baseAddress = GetModuleBaseAddress(moduleName);
    
    if (!baseAddress) {
        Napi::Error::New(env, "Failed to get module base address").ThrowAsJavaScriptException();
        return env.Null();
    }
    
    return Napi::BigInt::New(env, reinterpret_cast<uint64_t>(baseAddress));
}

Napi::Value HookManager::GetFunctionAddress(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    if (info.Length() < 2 || !info[0].IsString() || !info[1].IsNumber()) {
        Napi::TypeError::New(env, "Module name and RVA expected").ThrowAsJavaScriptException();
        return env.Null();
    }
    
    std::string moduleName = info[0].As<Napi::String>().Utf8Value();
    size_t rva = info[1].As<Napi::Number>().Int64Value();
    
    void* funcAddress = GetFunctionAddressByRVA(moduleName, rva);
    
    if (!funcAddress) {
        Napi::Error::New(env, "Failed to get function address").ThrowAsJavaScriptException();
        return env.Null();
    }
    
    return Napi::BigInt::New(env, reinterpret_cast<uint64_t>(funcAddress));
}

static void on_enter(GumInvocationListener* listener, GumInvocationContext* context) {
    // Hook 进入时的回调
    // 可以在这里修改参数、记录日志等
}

static void on_leave(GumInvocationListener* listener, GumInvocationContext* context) {
    // Hook 退出时的回调
    // 可以在这里修改返回值、记录日志等
}

Napi::Value HookManager::HookFunction(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    if (!fridaInitialized_) {
        Napi::Error::New(env, "Frida not initialized. Call initializeFrida() first").ThrowAsJavaScriptException();
        return Napi::Boolean::New(env, false);
    }
    
    // 参数: moduleName, rva, hookId
    if (info.Length() < 3 || !info[0].IsString() || !info[1].IsNumber() || !info[2].IsString()) {
        Napi::TypeError::New(env, "Expected (moduleName: string, rva: number, hookId: string)").ThrowAsJavaScriptException();
        return env.Undefined();
    }
    
    std::string moduleName = info[0].As<Napi::String>().Utf8Value();
    size_t rva = info[1].As<Napi::Number>().Int64Value();
    std::string hookId = info[2].As<Napi::String>().Utf8Value();
    
    // 获取函数地址
    void* targetFunc = GetFunctionAddressByRVA(moduleName, rva);
    if (!targetFunc) {
        Napi::Error::New(env, "Failed to get target function address").ThrowAsJavaScriptException();
        return Napi::Boolean::New(env, false);
    }
    
    // 创建 hook 信息
    auto hookInfo = std::make_shared<HookInfo>();
    hookInfo->targetFunc = targetFunc;
    hookInfo->moduleName = moduleName;
    hookInfo->rva = rva;
    
    // 创建 Frida 拦截器
    hookInfo->interceptor = gum_interceptor_obtain();
    
#ifdef _WIN32
    // Windows: 使用简单的监听器接口
    // 创建监听器
    GumInvocationListenerInterface iface = {};
    iface.on_enter = on_enter;
    iface.on_leave = on_leave;
    
    // 注意：Windows 可能需要不同的监听器实现
    // 暂时使用 NULL，因为 Windows attach 模式可能有问题
    hookInfo->listener = NULL;
    
    // 开始 hook
    gum_interceptor_begin_transaction(hookInfo->interceptor);
    GumAttachReturn ret = GUM_ATTACH_WRONG_SIGNATURE; // 标记为失败，强制使用其他方式
    gum_interceptor_end_transaction(hookInfo->interceptor);
#else
    // macOS/Linux: 使用自定义监听器类型
    hookInfo->listener = GUM_INVOCATION_LISTENER(g_object_new(TEST_TYPE_LISTENER, NULL));
    
    // 开始 hook
    gum_interceptor_begin_transaction(hookInfo->interceptor);
    GumAttachReturn ret = gum_interceptor_attach(
        hookInfo->interceptor,
        targetFunc,
        hookInfo->listener,
        NULL);
    gum_interceptor_end_transaction(hookInfo->interceptor);
#endif
    
    if (ret != GUM_ATTACH_OK) {
        std::stringstream ss;
        ss << "Frida hook failed with error code: " << ret;
        if (hookInfo->listener) g_object_unref(hookInfo->listener);
        g_object_unref(hookInfo->interceptor);
        Napi::Error::New(env, ss.str()).ThrowAsJavaScriptException();
        return Napi::Boolean::New(env, false);
    }
    
    // 保存 hook 信息
    hooks_[hookId] = hookInfo;
    
    return Napi::Boolean::New(env, true);
}

Napi::Value HookManager::UnhookFunction(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    if (info.Length() < 1 || !info[0].IsString()) {
        Napi::TypeError::New(env, "Hook ID expected").ThrowAsJavaScriptException();
        return env.Undefined();
    }
    
    std::string hookId = info[0].As<Napi::String>().Utf8Value();
    
    auto it = hooks_.find(hookId);
    if (it == hooks_.end()) {
        Napi::Error::New(env, "Hook not found").ThrowAsJavaScriptException();
        return Napi::Boolean::New(env, false);
    }
    
    // 恢复原始函数
    if (it->second->listener) {
        // attach 模式
        gum_interceptor_detach(it->second->interceptor, it->second->listener);
        g_object_unref(it->second->listener);
    } else {
        // replace 模式
        gum_interceptor_revert(it->second->interceptor, it->second->targetFunc);
    }
    
    // 清理资源
    g_object_unref(it->second->interceptor);
    
    hooks_.erase(it);
    return Napi::Boolean::New(env, true);
}
