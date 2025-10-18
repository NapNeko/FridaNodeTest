const addon = require('./build/Release/frida_hook_addon.node');

console.log('Frida Gum Hook Test (simple exports)');
console.log('===================\n');

try {
    // Init
    console.log('Init Frida Gum...');
    const inited = addon.Init();
    if (!inited) {
        console.log('✗ Init failed');
        process.exit(1);
    }
    console.log('✓ Init ok');

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
    const baseAddress = addon.getFunctionRva(moduleName, 0);
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
    const funcAddress = addon.getFunctionRva(moduleName, rva);
    console.log(`Function Address: 0x${funcAddress.toString(16)}`);
    if (funcAddress > 0n) {
        console.log('✓ Test 2 passed\n');
    } else {
        console.log('✗ Test 2 failed\n');
        process.exit(1);
    }

    // Test 3: Hook built-in test function
    console.log('Test 3: Hook built-in test function');
    console.log('  Hooking test function...');
    const hookSuccess = addon.hookTest();
    if (!hookSuccess) {
        console.log('    ✗ Failed to hook test function');
        process.exit(1);
    }
    console.log('    ✓ Hook installed successfully');
    console.log('    (Note) No direct call to internal function is exposed in this simplified addon, so we only assert installation success.');
    console.log('✓ Test 3 passed (install only)\n');

    console.log('===================');
    console.log('All tests passed! ✓');
    console.log('===================');
} catch (error) {
    console.error('\n✗ Test failed with error:', error.message);
    console.error(error.stack);
    process.exit(1);
}
