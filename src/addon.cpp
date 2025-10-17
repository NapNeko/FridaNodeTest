#include <napi.h>
#include "hook_manager.h"

// 初始化模块
Napi::Object Init(Napi::Env env, Napi::Object exports) {
    HookManager::Init(env, exports);
    return exports;
}

NODE_API_MODULE(dobby_hook_addon, Init)
