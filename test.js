const FridaHook = require('./index');

console.log('Frida Gum Hook Test');
console.log('===================\n');

try {
    const hook = new FridaHook();

    // Test 1: Get module base address
    console.log('Test 1: Get module base address');
    let moduleName;
    if (process.platform === 'win32') {
        moduleName = 'kernel32.dll';
    } else if (process.platform === 'darwin') {
        moduleName = 'libSystem.B.dylib';
    } else {
        moduleName = 'libc.so.6';
    }
    console.log(`Module: ${moduleName}`);
    const baseAddress = hook.getModuleBase(moduleName);
    console.log(`Base Address: 0x${baseAddress.toString(16)}`);
    if (baseAddress > 0n) {
        console.log('✓ Test 1 passed\n');
    } else {
        console.log('✗ Test 1 failed\n');
        process.exit(1);
    }

    // Test 2: Get function address by RVA
    console.log('Test 2: Get function address by RVA');
    const rva = 0x1000;
    console.log(`Module: ${moduleName}, RVA: 0x${rva.toString(16)}`);
    const funcAddress = hook.getFunctionAddress(moduleName, rva);
    console.log(`Function Address: 0x${funcAddress.toString(16)}`);
    if (funcAddress > 0n) {
        console.log('✓ Test 2 passed\n');
    } else {
        console.log('✗ Test 2 failed\n');
        process.exit(1);
    }

    // Test 3: Hook built-in test function
    console.log('Test 3: Hook built-in test function');
    
    // 3.1: Call original function
    console.log('  3.1: Calling original test function...');
    const originalResult = hook.callTestFunction();
    console.log(`    Original result: ${originalResult}`);
    if (originalResult !== 42) {
        console.log('    ✗ Original function should return 42');
        process.exit(1);
    }
    console.log('    ✓ Original function works correctly');
    
    // 3.2: Hook the function
    console.log('  3.2: Hooking test function...');
    const hookSuccess = hook.hookTestFunction();
    if (!hookSuccess) {
        console.log('    ✗ Failed to hook test function');
        process.exit(1);
    }
    console.log('    ✓ Hook installed successfully');
    
    // 3.3: Call hooked function
    console.log('  3.3: Calling hooked test function...');
    const hookedResult = hook.callTestFunction();
    console.log(`    Hooked result: ${hookedResult}`);
    if (hookedResult !== 99) {
        console.log('    ✗ Hooked function should return 99');
        process.exit(1);
    }
    console.log('    ✓ Hook working correctly - return value changed from 42 to 99');
    
    // 3.4: Unhook the function
    console.log('  3.4: Removing hook...');
    const unhookSuccess = hook.unhookFunction('test-function');
    if (!unhookSuccess) {
        console.log('    ✗ Failed to unhook test function');
        process.exit(1);
    }
    console.log('    ✓ Hook removed successfully');
    
    // 3.5: Call unhooked function
    console.log('  3.5: Calling unhooked test function...');
    const restoredResult = hook.callTestFunction();
    console.log(`    Restored result: ${restoredResult}`);
    if (restoredResult !== 42) {
        console.log('    ✗ Restored function should return 42');
        process.exit(1);
    }
    console.log('    ✓ Function restored to original behavior');
    
    console.log('✓ Test 3 passed\n');

    console.log('===================');
    console.log('All tests passed! ✓');
    console.log('===================');
} catch (error) {
    console.error('\n✗ Test failed with error:', error.message);
    console.error(error.stack);
    process.exit(1);
}
