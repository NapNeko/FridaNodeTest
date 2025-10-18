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
} = require('./index.js');

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
    //判断平台
    let addr;
    if (process.platform == 'win32') {
        addr = GetFunctionAddressByName('kernel32.dll', 'GetCurrentProcessId');
        console.log(`✓ GetCurrentProcessId address: ${addr}`);
    } else if (process.platform == 'linux') {
        addr = GetFunctionAddressByName('libc.so.6', 'getpid');
        console.log(`✓ getpid address: ${addr}`);
    } else if (process.platform == 'darwin') {
        addr = GetFunctionAddressByName('libSystem.B.dylib', 'getpid');
        console.log(`✓ getpid address: ${addr}`);
    }

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