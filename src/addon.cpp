#include <napi.h>

// Declarations from hook_manager.cpp
Napi::Value Init(const Napi::CallbackInfo& info);
Napi::Value GetFunctionAddressByRva(const Napi::CallbackInfo& info);
Napi::Value GetFunctionAddressByName(const Napi::CallbackInfo& info);
Napi::Value Hook(const Napi::CallbackInfo& info);
Napi::Value Unhook(const Napi::CallbackInfo& info);
Napi::Value CallFunctionNoArg(const Napi::CallbackInfo& info);

// Test functions
Napi::Value HookTest(const Napi::CallbackInfo& info);
Napi::Value CallTestFunction(const Napi::CallbackInfo& info);

// 初始化模块:导出所有函数
Napi::Object InitModule(Napi::Env env, Napi::Object exports) {
    // 核心 API
    exports.Set("Init", Napi::Function::New(env, Init, "Init"));
    exports.Set("GetFunctionAddressByRva", Napi::Function::New(env, GetFunctionAddressByRva, "GetFunctionAddressByRva"));
    exports.Set("GetFunctionAddressByName", Napi::Function::New(env, GetFunctionAddressByName, "GetFunctionAddressByName"));
    exports.Set("Hook", Napi::Function::New(env, Hook, "Hook"));
    exports.Set("Unhook", Napi::Function::New(env, Unhook, "Unhook"));
    exports.Set("CallFunctionNoArg", Napi::Function::New(env, CallFunctionNoArg, "CallFunctionNoArg"));
    
    // 测试函数
    exports.Set("HookTest", Napi::Function::New(env, HookTest, "HookTest"));
    exports.Set("CallTestFunction", Napi::Function::New(env, CallTestFunction, "CallTestFunction"));
    
    return exports;
}

NODE_API_MODULE(frida_hook_addon, InitModule)
