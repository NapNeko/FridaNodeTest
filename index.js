const addon = require('./build/Release/frida_hook_addon.node');

class FridaHook {
    constructor() {
        this.manager = new addon.HookManager();
        this.manager.initializeFrida();
    }

    /**
     * 获取模块基址
     * @param {string} moduleName - 模块名称 (例如: "kernel32.dll" 或 "libc.so.6")
     * @returns {BigInt} 模块基址
     */
    getModuleBase(moduleName) {
        return this.manager.getModuleBase(moduleName);
    }

    /**
     * 根据模块名和 RVA 获取函数地址
     * @param {string} moduleName - 模块名称
     * @param {number} rva - 相对虚拟地址
     * @returns {BigInt} 函数地址
     */
    getFunctionAddress(moduleName, rva) {
        return this.manager.getFunctionAddress(moduleName, rva);
    }

    /**
     * Hook 函数
     * @param {string} moduleName - 模块名称
     * @param {number} rva - 相对虚拟地址
     * @param {string} hookId - Hook 标识符
     * @returns {boolean} 是否成功
     */
    hookFunction(moduleName, rva, hookId) {
        return this.manager.hookFunction(moduleName, rva, hookId);
    }

    /**
     * 取消 Hook
     * @param {string} hookId - Hook 标识符
     * @returns {boolean} 是否成功
     */
    unhookFunction(hookId) {
        return this.manager.unhookFunction(hookId);
    }

    /**
     * 调用内置测试函数
     * @returns {number} 测试函数返回值
     */
    callTestFunction() {
        return this.manager.callTestFunction();
    }

    /**
     * Hook 内置测试函数
     * @returns {boolean} 是否成功
     */
    hookTestFunction() {
        return this.manager.hookTestFunction();
    }
}

module.exports = FridaHook;
