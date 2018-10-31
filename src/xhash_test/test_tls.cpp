#include <Windows.h>
#include "xhash.h"

static void __stdcall tlsCallback(PVOID dllHandle, DWORD reason, PVOID reserved);
static void __stdcall onProcessAttach(PVOID dllHandle);
static void __stdcall onThreadAttach(PVOID dllHandle);

#ifndef _WIN64
#pragma comment (linker, "/INCLUDE:__tls_used")
#pragma comment (linker, "/INCLUDE:_p_tls_callback")
#pragma data_seg(push)
#pragma data_seg(".CRT$XLC")
EXTERN_C PIMAGE_TLS_CALLBACK p_tls_callback = tlsCallback;
#pragma data_seg(pop)
#else
#pragma comment (linker, "/INCLUDE:_tls_used")
#pragma comment (linker, "/INCLUDE:p_tls_callback")
#pragma const_seg(push)
#pragma const_seg(".CRT$XLC")
EXTERN_C const PIMAGE_TLS_CALLBACK p_tls_callback = tlsCallback;
#pragma const_seg(pop)
#endif

static void __stdcall tlsCallback(PVOID dllHandle, DWORD reason, PVOID reserved)
{
    if (DLL_PROCESS_ATTACH == reason)
        onProcessAttach(dllHandle);
    else if (DLL_THREAD_ATTACH == reason)
        onThreadAttach(dllHandle);
    else
        ; // NOTHING
}

static void __stdcall onProcessAttach(PVOID dllHandle)
{
    const unsigned char md5Ntdll[16] = { 0x06, 0xf3, 0x2d, 0xb8, 0x2e, 0x57, 0x42, 0xc5, 0x1a, 0xe3, 0x05, 0x5b, 0xfb, 0xe1, 0xe0, 0xc5 };
    const unsigned char sha1Ntdll[20] = { 0x0E, 0xBD, 0x8D, 0x88, 0x9E, 0x0E, 0x2C, 0x63, 0xB7, 0xA4, 0x36, 0x1A, 0x8D, 0xFE, 0x00, 0x17, 0x7C, 0xDD, 0x90, 0xBB };
    const unsigned char sha256Ntdll[32] = { 0x97, 0x99, 0xDD, 0xA2, 0x25, 0x7C, 0xAF, 0xA9, 0x91, 0xAA, 0x38, 0xA1, 0x6B, 0xCA, 0x3F, 0xEF, 0x8E, 0x1D, 0xC7, 0x4A, 0x71, 0x0A, 0x45, 0x54, 0x0F, 0x92, 0xB1, 0xFA, 0x6B, 0xEB, 0xB3, 0x25 };
    unsigned char md5[16] = { 0 };
    unsigned char sha1[20] = { 0 };
    unsigned char sha256[32] = { 0 };
    XhMd5("ntdll.dll", 9, md5);
    XhSha1("ntdll.dll", 9, sha1);
    XhSha256("ntdll.dll", 9, sha256);
}

static void __stdcall onThreadAttach(PVOID dllHandle)
{
}