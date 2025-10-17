#ifndef HOOK_MANAGER_H
#define HOOK_MANAGER_H

#include <napi.h>
#include <string>
#include <map>
#include <memory>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#else
#include <dlfcn.h>
#include <link.h>
#endif

#include "frida-gum.h"

struct HookInfo {
    void* targetFunc;
    GumInterceptor* interceptor;
    GumInvocationListener* listener;
    std::string moduleName;
    size_t rva;
};

// 测试用的内置函数
extern "C" {
    int TestOriginalFunction();
    int TestReplacementFunction();
}

class HookManager : public Napi::ObjectWrap<HookManager> {
public:
    static Napi::Object Init(Napi::Env env, Napi::Object exports);
    HookManager(const Napi::CallbackInfo& info);
    ~HookManager();

private:
    static Napi::FunctionReference constructor;
    
    // Hook 方法
    Napi::Value HookFunction(const Napi::CallbackInfo& info);
    Napi::Value UnhookFunction(const Napi::CallbackInfo& info);
    Napi::Value GetModuleBase(const Napi::CallbackInfo& info);
    Napi::Value GetFunctionAddress(const Napi::CallbackInfo& info);
    Napi::Value InitializeFrida(const Napi::CallbackInfo& info);
    
    // 测试方法
    Napi::Value CallTestFunction(const Napi::CallbackInfo& info);
    Napi::Value HookTestFunction(const Napi::CallbackInfo& info);
    
    // 辅助方法
    void* GetModuleBaseAddress(const std::string& moduleName);
    void* GetFunctionAddressByRVA(const std::string& moduleName, size_t rva);
    
    std::map<std::string, std::shared_ptr<HookInfo>> hooks_;
    bool fridaInitialized_;
};

#endif // HOOK_MANAGER_H
