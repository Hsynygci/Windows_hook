

#include "stdafx.h"
#include <Windows.h>

bool Hook(void * toHook, void * ourFunct, int len) {
	if (len < 5) {
		return false;
	}

	DWORD curProtection;
	VirtualProtect(toHook, len, PAGE_EXECUTE_READWRITE, &curProtection);

	memset(toHook, 0x90, len);

	DWORD relativeAddress = ((DWORD)ourFunct - (DWORD)toHook) - 5;

	*(BYTE*)toHook = 0xE9;
	*(DWORD*)((DWORD)toHook + 1) = relativeAddress;

	DWORD temp;
	VirtualProtect(toHook, len, curProtection, &temp);

	return true;
}

DWORD jmpBackAddy;
void __declspec(naked) ourFunct() {
	__asm {
		add ecx, ecx
		mov edx, [ebp - 8]
		jmp[jmpBackAddy]
	}
}

DWORD WINAPI MainThread(LPVOID param) {
	int hookLength = 6;
	DWORD hookAddress = 0xB32768;
	jmpBackAddy = hookAddress + hookLength;

	Hook((void*)hookAddress, ourFunct, hookLength);

	while (true) {
		if (GetAsyncKeyState(VK_ESCAPE)) break;
		Sleep(50);
	}

	FreeLibraryAndExitThread((HMODULE)param, 0);

	return 0;
}

BOOL WINAPI DllMain(HINSTANCE hModule, DWORD dwReason, LPVOID lpReserved) {
	switch (dwReason) {
	case DLL_PROCESS_ATTACH:
		CreateThread(0, 0, MainThread, hModule, 0, 0);
		break;
	}

	return TRUE;
}