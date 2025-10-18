#include <napi.h>

// Declarations from hook_manager.cpp
Napi::Value Js_Init(const Napi::CallbackInfo& info);
Napi::Value Js_getFunctionRva(const Napi::CallbackInfo& info);
Napi::Value Js_hookTest(const Napi::CallbackInfo& info);

// 初始化模块：导出三个函数
Napi::Object InitModule(Napi::Env env, Napi::Object exports) {
    exports.Set("Init", Napi::Function::New(env, Js_Init, "Init"));
    exports.Set("getFunctionRva", Napi::Function::New(env, Js_getFunctionRva, "getFunctionRva"));
    exports.Set("hookTest", Napi::Function::New(env, Js_hookTest, "hookTest"));
    return exports;
}

NODE_API_MODULE(dobby_hook_addon, InitModule)
