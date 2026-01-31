#pragma once
#include "Bridge.hpp"
#include <windows.h>
#include <string>
#include <vector>
#include <thread>
#include "Utils/Process.hpp"
#include "Utils/Instance.hpp"
#include "Utils/Bytecode.hpp"

// Extracts embedded Lua initialization code from DLL resources
std::string ExtractEmbeddedLuaScript(DWORD targetPid, int resourceIndex) {
    try {
        HMODULE moduleHandle = NULL;
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            (LPCWSTR)&ExtractEmbeddedLuaScript,
            &moduleHandle
        );

        HRSRC resourceHandle = FindResourceW(moduleHandle, MAKEINTRESOURCEW(resourceIndex), RT_RCDATA);
        if (resourceHandle == NULL) {
            return "";
        }

        HGLOBAL loadedResource = LoadResource(moduleHandle, resourceHandle);
        if (loadedResource == NULL) {
            return "";
        }

        DWORD resourceSize = SizeofResource(moduleHandle, resourceHandle);
        void* resourceData = LockResource(loadedResource);

        std::string luaCode = std::string(static_cast<char*>(resourceData), resourceSize);

        // Replace PID placeholder with actual target process ID
        size_t placeholderPos = luaCode.find("%-PROCESS-ID-%");
        if (placeholderPos != std::string::npos) {
            luaCode.replace(placeholderPos, 14, std::to_string(targetPid));
        }

        return luaCode;
    }
    catch (...) {
        return "";
    }
}

// Core injection routine - locates target processes and injects initialization bytecode
int InitializeInjectionRoutine() {
    try {
        std::thread(StartBridge).detach();

        std::vector<DWORD> targetProcessIds = Process::GetProcessID();

        for (DWORD pid : targetProcessIds) {
            try {
                uintptr_t moduleBase = Process::GetModuleBase(pid);
                Instance datamodelRoot = FetchDatamodel(moduleBase, pid);

                size_t bytecodeSize;
                std::string initializationScript = ExtractEmbeddedLuaScript(pid, 1);

                // Compile and sign, then convert uint8_t to char
       // Bytecode::Sign already returns vector<char>, no conversion needed
                std::vector<char> signedBytecode = Bytecode::Sign(
                    Bytecode::Compile(initializationScript),
                    bytecodeSize
                );
   

                if (datamodelRoot.Name() == "Ugc") {
                    // Standard UGC injection path
                    Instance coreGuiInstance = datamodelRoot.FindFirstChild("CoreGui");
                    Instance robloxGuiInstance = coreGuiInstance.FindFirstChild("RobloxGui");
                    Instance modulesContainer = robloxGuiInstance.FindFirstChild("Modules");
                    Instance playerListModule = modulesContainer.FindFirstChild("PlayerList");
                    Instance playerListManager = playerListModule.FindFirstChild("PlayerListManager");

                    Instance corePackagesContainer = datamodelRoot.FindFirstChild("CorePackages");
                    Instance packagesContainer = corePackagesContainer.FindFirstChild("Packages");
                    Instance indexContainer = packagesContainer.FindFirstChild("_Index");
                    Instance collisionMatchersDir = indexContainer.FindFirstChild("CollisionMatchers2D");
                    Instance collisionMatchersModule = collisionMatchersDir.FindFirstChild("CollisionMatchers2D");
                    Instance jestModule = collisionMatchersModule.FindFirstChild("Jest");

                    // Enable module loading and swap script references
                    WriteMemory(moduleBase + Offsets::EnableLoadModule, 1, pid);
                    WriteMemory(playerListManager.GetAddress() + 0x8, jestModule.GetAddress(), pid);

                    auto revertBytecode = jestModule.SetScriptBytecode(signedBytecode, bytecodeSize);

                    // Force Roblox window to foreground and trigger ESC key
                    HWND targetWindow = Process::GetWindowsProcess(pid);
                    HWND previousWindow = GetForegroundWindow();

                    while (GetForegroundWindow() != targetWindow) {
                        SetForegroundWindow(targetWindow);
                        Sleep(1);
                    }

                    keybd_event(VK_ESCAPE, MapVirtualKey(VK_ESCAPE, 0), KEYEVENTF_SCANCODE, 0);
                    keybd_event(VK_ESCAPE, MapVirtualKey(VK_ESCAPE, 0), KEYEVENTF_SCANCODE | KEYEVENTF_KEYUP, 0);

                    coreGuiInstance.WaitForChild("HookRBX");
                    SetForegroundWindow(previousWindow);

                    // Restore original script reference
                    WriteMemory(playerListManager.GetAddress() + 0x8, playerListManager.GetAddress(), pid);
                    revertBytecode();
                }
                else {
                    // Delayed injection for non-UGC states - capture bytecode by value
                    std::thread([moduleBase, pid, signedBytecode, bytecodeSize]() {
                        try {
                            Instance pollingDatamodel = Instance(0, pid);

                            // Poll until UGC state is reached
                            while (true) {
                                pollingDatamodel = FetchDatamodel(moduleBase, pid);
                                if (pollingDatamodel.Name() == "Ugc") break;
                                Sleep(250);
                            }

                            Instance coreGuiInstance = pollingDatamodel.FindFirstChild("CoreGui");
                            Instance robloxGuiInstance = coreGuiInstance.FindFirstChild("RobloxGui");
                            Instance modulesContainer = robloxGuiInstance.FindFirstChild("Modules");
                            Instance avatarEditorModule = modulesContainer.FindFirstChild("AvatarEditorPrompts");

                            WriteMemory(moduleBase + Offsets::EnableLoadModule, 1, pid);
                            auto revertBytecode = avatarEditorModule.SetScriptBytecode(signedBytecode, bytecodeSize);

                            coreGuiInstance.WaitForChild("HookRBX");
                            revertBytecode();
                        }
                        catch (...) {
                            // Silent fail for thread exceptions
                        }
                        }).detach();
                }
            }
            catch (...) {
                // Continue to next process on failure
                continue;
            }
        }

        return 0;
    }
    catch (...) {
        return -1;
    }
}

// Converts wide character string to UTF-8 encoded std::string
std::string ConvertWideToUtf8(const wchar_t* wideString) {
    if (!wideString) return "";

    try {
        int requiredBufferSize = WideCharToMultiByte(
            CP_UTF8, 0,
            wideString, -1,
            nullptr, 0,
            nullptr, nullptr
        );

        if (requiredBufferSize == 0) return "";

        std::string convertedString(requiredBufferSize, 0);
        WideCharToMultiByte(
            CP_UTF8, 0,
            wideString, -1,
            &convertedString[0], requiredBufferSize,
            nullptr, nullptr
        );

        // Remove null terminator if present
        if (!convertedString.empty() && convertedString.back() == '\0') {
            convertedString.pop_back();
        }

        return convertedString;
    }
    catch (...) {
        return "";
    }
}

bool g_InjectionInitialized = false;

// DLL export: Initializes injection on first call, executes arbitrary Lua on subsequent calls
extern "C" __declspec(dllexport) void __cdecl InjectAndExecute(const wchar_t* luaSource) {
    try {
        if (!g_InjectionInitialized) {
            g_InjectionInitialized = true;

            FILE* consoleOutput = nullptr;
            AllocConsole();
            SetConsoleTitleA("HookRBX");
            freopen_s(&consoleOutput, "CONOUT$", "w", stdout);
            freopen_s(&consoleOutput, "CONOUT$", "w", stderr);

            InitializeInjectionRoutine();
        }

        std::string sourceCode = ConvertWideToUtf8(luaSource);
        if (sourceCode.length() >= 1) {
            Execute(sourceCode);
        }
    }
    catch (...) {
        // Silent fail - executor remains functional
    }
}