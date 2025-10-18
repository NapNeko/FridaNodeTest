const {
    Init,
    GetFunctionAddressByRva,
    GetFunctionAddressByName,
    Hook,
    Unhook,
    CallFunctionNoArg,
    GetHookInfo,
    CallOriginalFunction,
    HookTest,
    CallTestFunction
} = require('./test.js');

console.log('='.repeat(60));
console.log('Frida Hook - Complete API Demo');
console.log('='.repeat(60));

// 初始化
console.log('\n[Step 1] Initialize Frida-gum');
Init();
console.log('✓ Frida initialized');

// ============================================================================
// 演示 1: 通过 RVA 获取函数地址
// ============================================================================
console.log('\n' + '='.repeat(60));
console.log('[Demo 1] GetFunctionAddressByRva');
console.log('='.repeat(60));
console.log('\nUsage: GetFunctionAddressByRva(moduleName, rva)');
console.log('Example: const addr = GetFunctionAddressByRva("kernel32.dll", 0x12345);');
console.log('✓ Available');

// ============================================================================
// 演示 2: 通过函数名获取函数地址
// ============================================================================
console.log('\n' + '='.repeat(60));
console.log('[Demo 2] GetFunctionAddressByName');
console.log('='.repeat(60));

try {
    const addr = GetFunctionAddressByName('kernel32.dll', 'GetCurrentProcessId');
    console.log(`✓ GetCurrentProcessId address: ${addr}`);
    
    const pid = CallFunctionNoArg(addr);
    console.log(`✓ Current Process ID: ${pid}`);
} catch (error) {
    console.error('✗ Error:', error.message);
}

// ============================================================================
// 演示 3: Hook 和 Unhook
// ============================================================================
console.log('\n' + '='.repeat(60));
console.log('[Demo 3] Hook & Unhook');
console.log('='.repeat(60));

console.log('\n[3.1] Before hook:');
const result1 = CallTestFunction();
console.log(`  CallTestFunction() = ${result1}`);

console.log('\n[3.2] Installing hook:');
HookTest();
console.log('  ✓ Hook installed');

console.log('\n[3.3] After hook:');
const result2 = CallTestFunction();
console.log(`  CallTestFunction() = ${result2}`);

console.log('\n[3.4] Hook works:', result1 !== result2 ? '✓ Yes' : '✗ No');

// ============================================================================
// 演示 4: 调用被 hook 之前的原始函数
// ============================================================================
console.log('\n' + '='.repeat(60));
console.log('[Demo 4] Call Original Function');
console.log('='.repeat(60));
console.log('\nUsage: CallOriginalFunction(oriAddr)');
console.log('Note: This requires Hook to be called first and saves trampoline info');
console.log('✓ Available (use GetHookInfo to retrieve trampoline address)');

// ============================================================================
// API 总结
// ============================================================================
console.log('\n' + '='.repeat(60));
console.log('Complete API Reference');
console.log('='.repeat(60));

console.log('\n【核心 API】');
console.log('1. Init()');
console.log('   初始化 Frida-gum 引擎');
console.log('   Returns: boolean');
console.log('');
console.log('2. GetFunctionAddressByRva(moduleName: string, rva: number|bigint)');
console.log('   根据模块名和 RVA 获取函数绝对地址');
console.log('   Returns: BigInt');
console.log('');
console.log('3. GetFunctionAddressByName(moduleName: string, functionName: string)');
console.log('   根据模块名和导出函数名获取函数地址');
console.log('   Returns: BigInt');
console.log('');
console.log('4. Hook(oriAddr: BigInt, targetAddr: BigInt)');
console.log('   Hook 函数，返回 trampoline 地址用于调用原函数');
console.log('   Returns: BigInt (trampoline address)');
console.log('');
console.log('5. Unhook(oriAddr: BigInt)');
console.log('   取消 Hook');
console.log('   Returns: boolean');
console.log('');
console.log('6. CallFunctionNoArg(addr: BigInt)');
console.log('   调用无参数函数');
console.log('   Returns: number (int return value)');
console.log('');
console.log('7. GetHookInfo(oriAddr: BigInt)');
console.log('   获取 Hook 信息 (JS 层辅助函数)');
console.log('   Returns: { trampolineAddr, targetAddr } | null');
console.log('');
console.log('8. CallOriginalFunction(oriAddr: BigInt)');
console.log('   调用被 hook 的原始函数 (JS 层辅助函数)');
console.log('   Returns: number');

console.log('\n【测试 API】');
console.log('9. HookTest()');
console.log('   Hook 内置测试函数');
console.log('   Returns: boolean');
console.log('');
console.log('10. CallTestFunction()');
console.log('    调用内置测试函数');
console.log('    Returns: number');

console.log('\n' + '='.repeat(60));
console.log('Demo completed!');
console.log('='.repeat(60));
