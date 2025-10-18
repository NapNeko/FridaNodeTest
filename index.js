const addon = require('./build/Release/frida_hook_addon.node');

// 存储 hook 信息: oriAddr -> { trampolineAddr, targetAddr }
const hookMap = new Map();

/**
 * 初始化 Frida-gum
 * @returns {boolean} 是否成功
 */
function Init() {
    return addon.Init();
}

/**
 * 根据模块名和 RVA 获取函数地址
 * @param {string} moduleName - 模块名称 (例如: "kernel32.dll", "ntdll.dll")
 * @param {number|bigint} rva - 相对虚拟地址
 * @returns {BigInt} 函数的绝对地址
 */
function GetFunctionAddressByRva(moduleName, rva) {
    return addon.GetFunctionAddressByRva(moduleName, rva);
}

/**
 * 根据模块名和函数名获取函数地址
 * @param {string} moduleName - 模块名称 (例如: "kernel32.dll", "ntdll.dll")
 * @param {string} functionName - 函数名称 (例如: "CreateFileW", "NtCreateFile")
 * @returns {BigInt} 函数的绝对地址
 */
function GetFunctionAddressByName(moduleName, functionName) {
    return addon.GetFunctionAddressByName(moduleName, functionName);
}

/**
 * Hook 函数
 * @param {BigInt} oriAddr - 原始函数地址
 * @param {BigInt} targetAddr - 替换函数地址
 * @returns {BigInt} Trampoline 地址 (可用于调用原始函数)
 */
function Hook(oriAddr, targetAddr) {
    const trampolineAddr = addon.Hook(oriAddr, targetAddr);

    // 保存 hook 信息
    hookMap.set(oriAddr.toString(), {
        trampolineAddr,
        targetAddr
    });

    return trampolineAddr;
}

/**
 * 取消 Hook
 * @param {BigInt} oriAddr - 原始函数地址
 * @returns {boolean} 是否成功
 */
function Unhook(oriAddr) {
    const result = addon.Unhook(oriAddr);

    if (result) {
        hookMap.delete(oriAddr.toString());
    }

    return result;
}

/**
 * 调用无参函数
 * @param {BigInt} addr - 函数地址
 * @returns {number} 函数返回值 (int)
 */
function CallFunctionNoArg(addr) {
    return addon.CallFunctionNoArg(addr);
}

/**
 * 获取 Hook 信息
 * @param {BigInt} oriAddr - 原始函数地址
 * @returns {Object|null} Hook 信息 { trampolineAddr, targetAddr } 或 null
 */
function GetHookInfo(oriAddr) {
    return hookMap.get(oriAddr.toString()) || null;
}

/**
 * 调用被 hook 之前的原始函数 (无参数版本)
 * @param {BigInt} oriAddr - 原始函数地址
 * @returns {number} 原始函数返回值
 */
function CallOriginalFunction(oriAddr) {
    const hookInfo = GetHookInfo(oriAddr);
    if (!hookInfo) {
        throw new Error('Function is not hooked or hook info not found');
    }

    return CallFunctionNoArg(hookInfo.trampolineAddr);
}

// ============================================================================
// 测试函数
// ============================================================================

/**
 * Hook 内置测试函数
 * @returns {BigInt} Trampoline 地址 (可用于调用原始函数)
 */
function HookTest() {
    return addon.HookTest();
}

/**
 * 调用内置测试函数
 * @returns {number} 测试函数返回值
 */
function CallTestFunction() {
    return addon.CallTestFunction();
}

// ============================================================================
// 导出
// ============================================================================

module.exports = {
    // 核心 API
    Init,
    GetFunctionAddressByRva,
    GetFunctionAddressByName,
    Hook,
    Unhook,
    CallFunctionNoArg,
    GetHookInfo,
    CallOriginalFunction,

    // 测试函数
    HookTest,
    CallTestFunction
};
