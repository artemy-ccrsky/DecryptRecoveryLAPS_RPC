#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <locale.h>
#include <io.h>
#include <fcntl.h>
#include <rpc.h>
#include <rpcndr.h>

#ifdef __cplusplus
extern "C" {
#endif
#include "../Server/Server_h.h"
#ifdef __cplusplus
}
#endif

#pragma comment(lib, "rpcrt4.lib")

#define DEFAULT_PORT L"31337"

void PrintUsage(const wchar_t* progName)
{
    wprintf(L"Usage: %s <target> <authkey> <dn>\n", progName);
    wprintf(L"  target:  DC name or IP address and (optionally) interface port\n");
    wprintf(L"  authkey: Authentication key as a hex string\n");
    wprintf(L"  dn:      DN of the computer object to request password for\n");
}

void ParseAuthKey(const wchar_t* authKeyStr, size_t authKeyStrLen, unsigned char* authKey)
{
    for (int i = 0; i <= authKeyStrLen / 2; i++)
    {
        wchar_t byteStr[3] = { authKeyStr[i * 2], authKeyStr[i * 2 + 1], 0 };
        authKey[i] = (unsigned char)wcstol(byteStr, NULL, 16);
    }
}

void FormatTimestamp(const wchar_t* timestampStr, wchar_t* formattedTime)
{
    ULONGLONG fileTime = _wtoi64(timestampStr);
    FILETIME ft{};
    SYSTEMTIME st;

    ft.dwLowDateTime = (DWORD)(fileTime & 0xFFFFFFFF);
    ft.dwHighDateTime = (DWORD)(fileTime >> 32);

    FileTimeToSystemTime(&ft, &st);
    swprintf(
        formattedTime, 20, L"%04d/%02d/%02d %02d:%02d:%02d",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond
    );
}

void ParseTarget(const wchar_t* target, wchar_t* server, wchar_t* port)
{
    const wchar_t* colon = wcschr(target, L':');
    if (colon)
    {
        size_t serverLen = colon - target;
        wcsncpy(server, target, serverLen);
        server[serverLen] = L'\0';
        wcscpy(port, colon + 1);
    }
    else
    {
        wcscpy(server, target);
        wcscpy(port, DEFAULT_PORT);
    }
}

int wmain(int argc, wchar_t* argv[])
{
    _setmode(_fileno(stdout), _O_U8TEXT);
    _setmode(_fileno(stderr), _O_U8TEXT);
    setlocale(LC_ALL, "en_US.UTF-8");

    if (argc != 4)
    {
        PrintUsage(argv[0]);
        return 1;
    }

    wchar_t server[256] = { 0 };
    wchar_t port[16] = { 0 };
    ParseTarget(argv[1], server, port);

    const size_t authKeyStrLen = wcslen(argv[1]);
    auto* authKey = (unsigned char*)malloc(authKeyStrLen / 2);
    ParseAuthKey(argv[2], authKeyStrLen, authKey);

    const wchar_t* dn = argv[3];

    RPC_STATUS status;
    RPC_WSTR bindingString = NULL;
    wchar_t* result = NULL;

    status = RpcStringBindingComposeW(
        NULL,
        (RPC_WSTR)L"ncacn_ip_tcp",
        (RPC_WSTR)server,
        (RPC_WSTR)port,
        NULL,
        &bindingString
    );

    if (status != RPC_S_OK)
    {
        wprintf(L"[-] RpcStringBindingCompose failed: %d\n", status);
        goto cleanup;
    }

    status = RpcBindingFromStringBindingW(bindingString, &ImplicitHandle);
    if (status != RPC_S_OK)
    {
        wprintf(L"[-] RpcBindingFromStringBinding failed: %d\n", status);
        goto cleanup;
    }

    RpcTryExcept
    {
        status = DecryptPassword(dn, authKey, sizeof(authKey), &result);
    }
    RpcExcept(1)
    {
        wprintf(L"[-] RPC exception occurred: %d\n", RpcExceptionCode());
        goto cleanup;
    }
    RpcEndExcept;

    if (status != RPC_S_OK)
    {
        wprintf(L"[-] RPC call failed with status: %d\n", status);
    }
    else if (result == NULL)
    {
        wprintf(L"[-] No password returned\n");
    }
    else
    {
        wchar_t* sep = wcschr(result, L'|');
        if (sep)
        {
            *sep = L'\0';
            wchar_t formattedTime[20] = { 0 };
            FormatTimestamp(result, formattedTime);

            wchar_t account[64] = { 0 };
            wchar_t password[64] = { 0 };

            wchar_t* accountStart = wcsstr(sep + 1, L"\"n\":\"");
            if (accountStart)
            {
                accountStart += 5;
                wchar_t* accountEnd = wcschr(accountStart, L'"');
                if (accountEnd)
                {
                    wcsncpy(account, accountStart, accountEnd - accountStart);
                    account[accountEnd - accountStart] = L'\0';
                }
            }

            wchar_t* passwordStart = wcsstr(sep + 1, L"\"p\":\"");
            if (passwordStart)
            {
                passwordStart += 5;
                wchar_t* passwordEnd = wcschr(passwordStart, L'"');
                if (passwordEnd)
                {
                    wcsncpy(password, passwordStart, passwordEnd - passwordStart);
                    password[passwordEnd - passwordStart] = L'\0';
                }
            }

            wprintf(L"Account             : %s\n", account);
            wprintf(L"Password            : %s\n", password);
            wprintf(L"ExpirationTimestamp : %s\n", formattedTime);
        }
        else
        {
            wprintf(L"[+] Password: %s\n", result);
        }
    }

cleanup:
    if (result)
        MIDL_user_free(result);
    if (bindingString)
        RpcStringFreeW(&bindingString);
    if (ImplicitHandle)
        RpcBindingFree(&ImplicitHandle);
    if (authKey)
        free(authKey);

    return status == RPC_S_OK ? 0 : status;
}

void* __RPC_USER midl_user_allocate(size_t size)
{
    return malloc(size);
}

void __RPC_USER midl_user_free(void* p)
{
    free(p);
}
