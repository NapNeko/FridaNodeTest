# Frida Gum Hook Test Library

一个基于 [Frida Gum](https://frida.re/) 框架的 Node.js Native Addon，使用 cmake-js 构建，支持通过模块名 + RVA 实现函数 hook。

## 功能特性

- ✅ 通过模块名和 RVA 获取函数地址
- ✅ 获取模块基址
- ✅ 支持函数 Hook
- ✅ 支持取消 Hook
- ✅ 跨平台支持 (Windows/Linux/macOS)

## 前置要求

- Node.js >= 18.x
- CMake >= 3.15
- C++ 编译器 (MSVC/GCC/Clang)
- Git

### Windows
- Visual Studio 2019 或更高版本 (含 C++ 开发工具)
- 或 Build Tools for Visual Studio

### Linux
```bash
sudo apt-get install cmake ninja-build build-essential
```

### macOS
```bash
brew install cmake ninja
```

## 安装

```bash
npm install
```

## 构建

**首次构建**: CMake 会自动从 GitHub 下载 Frida Gum DevKit (~66MB)，缓存到 `.frida-devkit/` 目录

### 方式 1: 使用 npm 脚本
```bash
# 首次安装（自动下载 Frida DevKit）
npm install

# 重新构建
npm run build
```

### 方式 2: 使用构建脚本

**Windows (PowerShell):**
```powershell
# 基本构建
.\build.ps1

# 清理并测试
.\build.ps1 -Clean -Test

# 详细输出
.\build.ps1 -Verbose
```

**Linux/macOS:**
```bash
# 添加执行权限
chmod +x build.sh

# 基本构建
./build.sh

# 清理并测试
./build.sh --clean --test

# 详细输出
./build.sh --verbose
```

### 方式 3: 使用 VS Code 任务
按 `Ctrl+Shift+B` 或 `Cmd+Shift+B` 选择构建任务

## 使用方法

```javascript
const FridaHook = require('./index');

const hook = new FridaHook();

// 获取模块基址
const moduleName = process.platform === 'win32' ? 'kernel32.dll' : 'libc.so.6';
const baseAddress = hook.getModuleBase(moduleName);
console.log(`Base Address: 0x${baseAddress.toString(16)}`);

// 通过模块名和 RVA 获取函数地址
const rva = 0x1000;
const funcAddress = hook.getFunctionAddress(moduleName, rva);
console.log(`Function Address: 0x${funcAddress.toString(16)}`);

// Hook 函数 (需要实现替换函数)
const hookId = 'my-hook-1';
const success = hook.hookFunction(moduleName, rva, hookId);
console.log(`Hook ${success ? 'successful' : 'failed'}`);

// 取消 Hook
hook.unhookFunction(hookId);
```

## API 文档

### `new DobbyHook()`

创建一个新的 DobbyHook 实例。

### `getModuleBase(moduleName)`

获取指定模块的基址。

- **参数:**
  - `moduleName` (string): 模块名称，例如 "kernel32.dll" (Windows) 或 "libc.so.6" (Linux)
- **返回:** BigInt - 模块基址

### `getFunctionAddress(moduleName, rva)`

根据模块名和 RVA 获取函数地址。

- **参数:**
  - `moduleName` (string): 模块名称
  - `rva` (number): 相对虚拟地址
- **返回:** BigInt - 函数地址

### `hookFunction(moduleName, rva, hookId)`

Hook 指定的函数。

- **参数:**
  - `moduleName` (string): 模块名称
  - `rva` (number): 相对虚拟地址
  - `hookId` (string): Hook 标识符，用于后续取消 Hook
- **返回:** boolean - 是否成功

### `unhookFunction(hookId)`

取消指定的 Hook。

- **参数:**
  - `hookId` (string): Hook 标识符
- **返回:** boolean - 是否成功

## 测试

```bash
npm test
```

## CI/CD

项目包含 GitHub Actions workflow，会在以下情况自动构建和测试：
- Push 到 main 或 develop 分支
- 创建 Pull Request
- 手动触发

支持的平台：
- Ubuntu (Linux)
- Windows
- macOS

支持的 Node.js 版本：
- 18.x
- 20.x

## 开发

### VS Code 调试
1. 按 `F5` 运行测试并调试
2. 在 `test.js` 中设置断点
3. 查看变量和调用堆栈

### 本地构建测试
```bash
# Windows
.\build.ps1 -Clean -Test -Verbose

# Linux/macOS
./build.sh --clean --test --verbose
```

## 依赖

- [cmake-js](https://github.com/cmake-js/cmake-js) - CMake 构建工具
- [node-addon-api](https://github.com/nodejs/node-addon-api) - Node.js C++ Addon API
- [Frida Gum](https://frida.re/) - 强大的跨平台 instrumentation 框架

## 优势

- ✅ **跨平台**: 完美支持 Windows、Linux、macOS
- ✅ **MSVC 兼容**: 使用预编译的 Frida DevKit，无需复杂编译
- ✅ **功能强大**: Frida Gum 提供了丰富的 instrumentation API
- ✅ **稳定可靠**: Frida 是业界标准的动态分析工具

## 注意事项

1. Frida DevKit 会在首次构建时自动下载
2. Hook 系统函数需要管理员权限
3. 确保你有权限访问目标模块和函数
4. RVA 地址需要准确，可以使用 IDA、Ghidra 等工具获取

## 许可证

MIT
