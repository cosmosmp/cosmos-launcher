#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <filesystem>
#include <TlHelp32.h>
#include <stdio.h>
#include <fstream>
#include <string>
#include <regex>
#include <vector>
#include <iostream>
#include <winsock2.h>
#include <format>

namespace fs = std::filesystem;

#define internal        static
#define local_persist   static

void
ShutdownError(const char* cMessage) {
#if defined(_WIN32)
    local_persist wchar_t buf[256];
    FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, 0, WSAGetLastError(), 0, buf, 256, 0);
    wchar_t* nl = wcsrchr(buf, L'\n');
    if (nl) *nl = 0;
    char mbBuf[512];
    size_t numConverted;
    wcstombs_s(&numConverted, mbBuf, sizeof(mbBuf), buf, _TRUNCATE);
    fprintf_s(stderr, "%s. %s", cMessage, mbBuf);
#else
    local_persist thread_local char buf[256];
    strerror_r(errno, buf, sizeof(buf));
    fprintf_s(stderr, "%s\nError: %s", cMessage, buf);
#endif

    getchar();
    exit(1);
}


char*
GetSteamPath()
{
    HKEY hSteamKey;
    char* cSteamPath = nullptr;
    DWORD dwLen = 0;

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, R"(SOFTWARE\WOW6432Node\Valve\Steam)", 0, KEY_QUERY_VALUE, &hSteamKey) ==
        ERROR_SUCCESS) {
        if (RegQueryValueExA(hSteamKey, "InstallPath", nullptr, nullptr, nullptr, &dwLen) == ERROR_SUCCESS) {
            cSteamPath = new char[dwLen];
            if (RegQueryValueExA(hSteamKey, "InstallPath", nullptr, nullptr, reinterpret_cast<LPBYTE>(cSteamPath), &dwLen) == ERROR_SUCCESS) {
                cSteamPath[dwLen - 1] = '\0';
            } else {
                delete[] cSteamPath;
                cSteamPath = nullptr;
            }
        }
        RegCloseKey(hSteamKey);
    }

    return cSteamPath;
}

std::string
GetGamePath(std::string sSteamPath, std::string sName, std::string sExePath)
{
    char cFullPath[MAX_PATH] = { 0 };
    {
        sprintf_s(cFullPath, MAX_PATH, "%s\\steamapps\\common\\%s\\%s", sSteamPath.c_str(), sName.c_str(), sExePath.c_str());
        if (fs::exists(cFullPath))
            return std::string(cFullPath);
    }

    {
        char cLibFoldersPath[MAX_PATH];
        sprintf_s(cLibFoldersPath, MAX_PATH, "%s\\%s", sSteamPath.c_str(), "steamapps\\libraryfolders.vdf");

        std::ifstream f(cLibFoldersPath);
        if (!f.is_open())
        {
            fprintf(stderr, "Could not open \"%s\".\n", cLibFoldersPath);
            return "";
        }

        std::string line;
        std::vector<std::string> cPaths;
        while (std::getline(f, line))
        {
            // Check if the line contains "path"
            size_t pos = line.find("\"path\"");
            if (pos != std::string::npos)
            {
                // Extract the path from the line
                pos = line.find('"', pos + 6);
                if (pos != std::string::npos)
                {
                    size_t endpos = line.find('"', pos + 1);
                    if (endpos != std::string::npos)
                    {
                        std::string path = line.substr(pos + 1, endpos - pos - 1);
                        cPaths.push_back(path);
                    }
                }
            }
        }

        f.close();

        for (std::string path : cPaths)
        {
            sprintf_s(cFullPath, MAX_PATH, "%s\\steamapps\\common\\%s\\%s", path.c_str(), sName.c_str(), sExePath.c_str());
            if (fs::exists(cFullPath))
                return std::string(cFullPath);
        }
    }

    return "";
}

std::string
get_base_dir(std::string path) {
    std::string fullPath(path);
    size_t lastSlash = fullPath.find_last_of("\\/");
    if (lastSlash == std::string::npos) {
        return "";
    } else {
        return fullPath.substr(0, lastSlash);
    }
}

std::wstring
s2ws(const std::string& s) {
    int len;
    int slength = (int)s.length() + 1;
    len = MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, 0, 0);
    wchar_t* buf = new wchar_t[len];
    MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, buf, len);
    std::wstring r(buf);
    delete[] buf;
    return r;
}

int main(int argc, char** argv)
{
    std::string sInputDir = fs::current_path().string();
    if (argc >= 2)
        sInputDir = argv[1];

    char cDllPath[MAX_PATH];
    sprintf_s(cDllPath, MAX_PATH, "%s\\%s", sInputDir.c_str(), "cosmos-client.dll");
    if (!fs::exists(cDllPath))
    {
        MessageBoxA(NULL, std::format("Unable to find dll in {}.", cDllPath).c_str(), "CosmosMP Launcher", MB_OK | MB_ICONERROR);
        return 1;
    }

    const char* cSteamPath = GetSteamPath();
    std::string sBeamNGPath = GetGamePath(std::string(cSteamPath), "BeamNG.drive", "Bin64\\BeamNG.drive.x64.exe");
    if (sBeamNGPath.empty())
    {
        MessageBoxA(NULL, "Unable to find BeamNG", "CosmosMP Launcher", MB_OK | MB_ICONERROR);
        return 1;
    }

    std::string cBaseDir = get_base_dir(std::string(sBeamNGPath));

    // Set the SteamAppId so steam initializes
    SetEnvironmentVariableA("SteamAppId", "284160");

    STARTUPINFOW si;
    ZeroMemory(&si, sizeof(STARTUPINFOW));

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(LPPROCESS_INFORMATION));

    // Root Directory
    std::wstring wsRootDir = std::wstring(cBaseDir.begin(), cBaseDir.end());
    LPCWSTR lwsRootDir = wsRootDir.c_str();

    // Executable Location
    wchar_t wtext[MAX_PATH];
    mbstowcs(wtext, sBeamNGPath.c_str(), strlen(sBeamNGPath.c_str()) + 1);
    LPWSTR lpwCommandLine = wtext;

    if (!CreateProcessW(NULL, lpwCommandLine, NULL, NULL, TRUE,
                        CREATE_DEFAULT_ERROR_MODE | CREATE_SUSPENDED, NULL, lwsRootDir , &si, &pi)) {
        ShutdownError("CreateProcessA Failed");
    }

    // Inject DLL
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32) {
        ShutdownError("GetModuleHandleW(kernel32.dll) failed");
    }

    LPVOID pLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryA");
    if (!pLoadLibrary) {
        ShutdownError("GetProcAddress(LoadLibraryA) failed");
    }

    // Allocate memory for DLL path
    LPVOID pDllPath = VirtualAllocEx(pi.hProcess, NULL, strlen(cDllPath), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!pDllPath) {
        ShutdownError("VirtualAllocEx failed");
    }

    // Write DLL path to process memory
    if (!WriteProcessMemory(pi.hProcess, pDllPath, cDllPath, strlen(cDllPath), NULL)) {
        ShutdownError("WriteProcessMemory failed");
    }

    // Create remote thread to load DLL
    HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibrary, pDllPath, 0, NULL);
    if (!hThread) {
        ShutdownError("CreateRemoteThread failed");
    }

    // Wait for thread to finish loading DLL
    if (WaitForSingleObject(hThread, INFINITE) != WAIT_OBJECT_0) {
        ShutdownError("WaitForSingleObject failed");
    }

    // Resume game process
    if (ResumeThread(pi.hThread) == (DWORD)-1) {
        ShutdownError("ResumeThread failed");
    }

    // Cleanup
    CloseHandle(hThread);
    VirtualFreeEx(pi.hProcess, pDllPath, 0, MEM_RELEASE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return 0;
}