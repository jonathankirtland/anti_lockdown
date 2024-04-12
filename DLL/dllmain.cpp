//this file contains the hooks and the logic for the hooks. it also contains the logic for the registry key setting and the window resizing. this is the primary file for DLL creation.
//compile and build as X86 Release
//this file is compiled as a DLL and injected into the Lockdown Browser process

#include "stdafx.h"
#include "structs.h"


#define DEBUG
int width = 800, height = 600;


auto shrink = VK_F2;
auto grow = VK_F3;



//function prototypes
tTerminateProcess ogTerminateProcess;
tGetForegroundWindow ogGetForegroundWindow;
PNT_QUERY_SYSTEM_INFORMATION ogNtQuerySystemInformation;
tEnumWindows originalEnumWindows = nullptr;
tGetDesktopWindow originalGetDesktopWindow = nullptr;
tEmptyClipboard ogEmptyClipboard;
tMessageBoxA ogMessageBoxA;

HWND g_hMainWnd;
BOOL firstTimeuWu = TRUE;
HHOOK hkeyboardhook = NULL;
BOOL fullscreen = TRUE;

BOOL SetWindowFullscreen(HWND hwnd)
{
	int screenWidth = GetSystemMetrics(SM_CXSCREEN);
	int screenHeight = GetSystemMetrics(SM_CYSCREEN);

	return SetWindowPos(hwnd, HWND_TOP, 0, 0, screenWidth, screenHeight, SWP_NOMOVE | SWP_NOZORDER);
}

BOOL IsStringEqual(IN LPCWSTR Str1, IN LPCWSTR Str2) {

	WCHAR	lStr1[MAX_PATH],
			lStr2[MAX_PATH];

	int		len1 = lstrlenW(Str1),
			len2 = lstrlenW(Str2);

	int		i = 0,
			j = 0;

	// checking - we dont want to overflow our buffers
	if (len1 >= MAX_PATH || len2 >= MAX_PATH)
		return FALSE;

	// converting Str1 to lower case string (lStr1)
	for (i = 0; i < len1; i++) 
	{
		lStr1[i] = (WCHAR)tolower(Str1[i]);
	}

	lStr1[i++] = L'\0'; // null terminating


	// converting Str2 to lower case string (lStr2)
	for (j = 0; j < len2; j++) 
	{
		lStr2[j] = (WCHAR)tolower(Str2[j]);
	}

	lStr2[j++] = L'\0'; // null terminating


	// comparing the lower-case strings
	if (lstrcmpiW(lStr1, lStr2) == 0)
		return TRUE;

	return FALSE;
}

HMODULE GetModuleHandles() {

	// Getting PEB
#ifdef _WIN64 // if compiling as x64
	PPEB			pPeb = (PEB*)(__readgsqword(0x60));
#elif _WIN32 // if compiling as x32
	PPEB			pPeb = (PEB*)(__readfsdword(0x30));
#endif

	printf("[+] PEB: %p\n", pPeb);
	printf("[+] PEB_LDR_DATA: %p\n", pPeb->Ldr);
	printf("[+] printing modules: \n");

	// Getting Ldr
	PPEB_LDR_DATA		    pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);

	// Getting the first element in the linked list which contains information about the first module
	PLDR_DATA_TABLE_ENTRY	pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);

	//get the first module, it is the application itself
	if (pDte->FullDllName.Length != NULL)
	{
		wprintf(L"[+] Application Name: \"%s\" \n", pDte->FullDllName.Buffer);
		pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);
	}


	while (pDte) {

		// If not null
		if (pDte->FullDllName.Length != NULL) {
			// Print the DLL name
			wprintf(L"\t[i] Module Name: \"%s\" \n", pDte->FullDllName.Buffer);

		}
		else {
			break;
		}

		// Next element in the linked list
		pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);

	}

	return NULL;
}

HMODULE RemoveModuleFromPEB(IN LPCWSTR szModuleName) {

	BOOL					bFound = FALSE;

#ifdef _WIN64
	PPEB					pPeb = (PEB*)(__readgsqword(0x60));
#elif _WIN32
	PPEB					pPeb = (PEB*)(__readfsdword(0x30));
#endif

	PLDR_DATA_TABLE_ENTRY	pDte = (PLDR_DATA_TABLE_ENTRY)(pPeb->Ldr->InMemoryOrderModuleList.Flink);

	// getting the head of the linked list ( used to get the node & to check the end of the list)
	PLIST_ENTRY				pListHead = (PLIST_ENTRY)&pPeb->Ldr->InMemoryOrderModuleList;
	// getting the node of the linked list
	PLIST_ENTRY				pListNode = (PLIST_ENTRY)pListHead->Flink;

	do
	{
		if (pDte->FullDllName.Length != NULL) {
			if (IsStringEqual(pDte->FullDllName.Buffer, szModuleName)) {


				//slide the linked list to remove the node
#ifdef DEBUG				
				wprintf(L"[+] Found Dll \"%s\" \n", pDte->FullDllName.Buffer);
				wprintf(L"[+] Removing Dll \"%s\" \n", pDte->FullDllName.Buffer);
#endif // DEBUG
				pListNode->Blink->Flink = pListNode->Flink;
#ifdef DEBUG
				wprintf(L"[i] updating the Flink of the previous node\n");
#endif // 
				pListNode->Flink->Blink = pListNode->Blink;
#ifdef DEBUG
				wprintf(L"[i] updating the Blink of the next node\n");
				wprintf(L"[i] linked list fixed\n");
#endif // DEBUG

				bFound = TRUE;

#ifdef STRUCTS
				return (HMODULE)(pDte->InInitializationOrderLinks.Flink);
#else
				return (HMODULE)pDte->Reserved2[0];
#endif // STRUCTS
			}

			//wprintf(L"[i] \"%s\" \n", pDte->FullDllName.Buffer);

			// updating pDte to point to the next PLDR_DATA_TABLE_ENTRY in the linked list
			pDte = (PLDR_DATA_TABLE_ENTRY)(pListNode->Flink);

			// updating the node variable to be the next node in the linked list
			pListNode = (PLIST_ENTRY)pListNode->Flink;

		}

		// when the node is equal to the head, we reached the end of the linked list, so we break out of the loop
	} while (pListNode != pListHead);

	if (!bFound) {
#ifdef DEBUG
		wprintf(L"[!] Dll \"%s\" not found\n", szModuleName);
#endif // DEBUG

		}



	return NULL;
}





int WINAPI hkMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType, WORD wLanguageId)
{
	printf("[*] MessageBoxA called\n");
	return 6;
}




BOOL hkEmptyClipboard()
{
	return TRUE;
}


// registry key set
bool SetRegistryKeyDword(HKEY hKey, LPCSTR subKey, LPCSTR valueName, DWORD value) {
	HKEY hSubKey;
	LONG lResult;

	// Open the specified key
	lResult = RegOpenKeyExA(hKey, subKey, 0, KEY_WRITE, &hSubKey);
	if (lResult != ERROR_SUCCESS) {
		std::cerr << "[!] Error opening key: " << lResult << '\n';
		return false;
	}

	// Set the value
	lResult = RegSetValueExA(hSubKey, valueName, 0, REG_DWORD, reinterpret_cast<const BYTE*>(&value), sizeof(value));
	if (lResult != ERROR_SUCCESS)
	{
		std::cerr << "[!] Error setting key value: " << lResult << '\n';
		// It's important to close the opened key even when an error occurs
		RegCloseKey(hSubKey);
		return false;
	}

	// Close the key
	lResult = RegCloseKey(hSubKey);
	if (lResult != ERROR_SUCCESS) {
		std::cerr << "[!] Error closing key: " << lResult << '\n';
		return false;
	}

	return true;
}

// just a wrapper for ease
BOOL SetWindowSize(HWND hWnd, int width, int height)
{
	// The parameters for SetWindowPos are as follows:
	// hWnd: Handle to the window
	// hWndInsertAfter: A handle to the window to precede the positioned window in the Z order
	//                  (use one of the special values, e.g., HWND_TOP)
	// X: New position of the left side of the window
	// Y: New position of the top of the window
	// cx: New width of the window
	// cy: New height of the window
	// uFlags: Window sizing and positioning flags

	return SetWindowPos(hWnd, HWND_TOP, 0, 0, width, height, SWP_NOMOVE | SWP_NOZORDER);
}


// get foregroudnwindow but we only return the pseudo handle of the browser
HWND WINAPI hkGetForegroundWindow()
{
	g_hMainWnd = FindWindowA("CEFCLIENT", NULL);
	return g_hMainWnd;
}

// fix the taskbar
BOOL FixTaskBar()
{
	HWND shell_wnd = FindWindow(L"Shell_TrayWnd", NULL);
	if (!shell_wnd)
		return FALSE;
	ShowWindow(shell_wnd, SW_SHOW);
	printf("[+] Fixed taskbar \n");
	return TRUE;
}

HWND WINAPI hkGetDesktopWindow()
{
#ifdef DEBUG
	printf("[*] Lockdown Browser is attempting to take a screenshot\n[+] screenshot prevented\n");
	//list the sub calls this hwnd may be used for to take a screenshot and tab them out in the print statement
#endif // DEBUG

	return g_hMainWnd;
}

BOOL WINAPI hkTerminateProcess(HANDLE hProcess, UINT uExitCode)
{

#ifdef DEBUG
	printf("[*] Im a naughty boy and I tried to kill: %p\n", (VOID*)hProcess);
#endif // DEBUG

	return TRUE;
}

NTSTATUS WINAPI HookedNtQuerySystemInformation(
	__in       SYSTEM_INFORMATION_CLASS SystemInformationClass,
	__inout    PVOID                    SystemInformation,
	__in       ULONG                    SystemInformationLength,
	__out_opt  PULONG                   ReturnLength
)
{


	NTSTATUS status = ogNtQuerySystemInformation(SystemInformationClass,
		SystemInformation,
		SystemInformationLength,
		ReturnLength);
	if (SystemProcessInformation == SystemInformationClass && STATUS_SUCCESS == status)
	{
		// Loop through the list of processes
		PMY_SYSTEM_PROCESS_INFORMATION pCurrent = NULL;
		PMY_SYSTEM_PROCESS_INFORMATION pNext = (PMY_SYSTEM_PROCESS_INFORMATION)
			SystemInformation;

		do
		{
			// remove the current entry
			pCurrent = pNext;
			pNext = (PMY_SYSTEM_PROCESS_INFORMATION)((PUCHAR)pCurrent + pCurrent->
				NextEntryOffset);

			if (!pNext->NextEntryOffset)
			{
				pCurrent->NextEntryOffset = 0;
			}
			else
			{
				pCurrent->NextEntryOffset += pNext->NextEntryOffset;
			}
			pNext = pCurrent;

		} while (pCurrent->NextEntryOffset != 0);
	}
	return status;
}

HDC WINAPI hkCreateCompatibleDC(HDC hdc)
{
	return hdc;
}


LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam)
{
	if (nCode >= 0)
	{
		if (wParam == WM_KEYDOWN)
		{
			KBDLLHOOKSTRUCT* pKeyboardHookStruct = (KBDLLHOOKSTRUCT*)lParam;
			if (pKeyboardHookStruct->vkCode == shrink)
			{
				printf("[*] F2 key pressed\n");
				if (fullscreen)
				{
					HWND tstWindow = FindWindowA("CEFCLIENT", NULL);
					SetWindowSize(tstWindow, width, height);
					HWND canvasWindow = FindWindowA("LOCKDOWNCHROME", NULL);
					SetWindowSize(canvasWindow, width, height);
					HWND coverWindow = FindWindowA("Respondus LockDown Browser CW", NULL);
					SetWindowSize(coverWindow, 200, 200);
					printf("[+] Windows fixed\n");
					fullscreen = FALSE;
				}
				if (firstTimeuWu)
				{

#ifdef DEBUG
					printf("[+] MessageBoxA hooked\n");
					printf("[+] NtQuerySystemInformation hooked\n");
					printf("[+] GetForegroundWindow hooked\n");
					printf("[+] TerminateProcess hooked\n");
					printf("[+] GetDesktopWindow hooked\n");
					printf("[+] EmptyClipboard hooked\n");
#endif // DEBUG


					SetRegistryKeyDword(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "DisableTaskMgr", 0x0);
#ifdef DEBUG
					printf("[+] unset key: DisableTaskMgr\n");
#endif // DEBUG


					SetRegistryKeyDword(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", "NoChangeStartMenu", 0x0);
#ifdef DEBUG
					printf("[+] unset key: NoChangeStartMenu\n");
#endif // DEBUG


					SetRegistryKeyDword(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", "NoClose", 0x0);
#ifdef DEBUG
					printf("[+] unset key: NoClose\n");
#endif // DEBUG

					SetRegistryKeyDword(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", "NoLogOff", 0x0);
#ifdef DEBUG
					printf("[+] unset key: NoLogOff\n");
					printf("[+] registry keys reset\n");
#endif // DEBUG

#ifdef DEBUG
					HMODULE hModule = GetModuleHandles();
#endif // DEBUG
					HMODULE hModule3 = RemoveModuleFromPEB(L"DLL.dll");
					if (hModule3 == NULL)
					{
#ifdef DEBUG
						printf("[+] DLL not found, SUCCESS!\n");
#endif // DEBUG


					}
					else
					{
#ifdef DEBUG
						printf("[!] DLL found, FAILURE!\n");
#endif // DEBUG
					}

					FixTaskBar();
#ifdef DEBUG
					
					printf("[+] First time flag set to false\n");
					printf("[!] Task Killing Beginnning: \n");
#endif // DEBUG
					firstTimeuWu = FALSE;
				}
			}
			else if (pKeyboardHookStruct->vkCode == grow)
			{
				if (!fullscreen)
				{
					HWND tstWindow = FindWindowA("CEFCLIENT", NULL);
					HWND canvasWindow = FindWindowA("LOCKDOWNCHROME", NULL);
					HWND coverWindow = FindWindowA("Respondus LockDown Browser CW", NULL);

					SetWindowFullscreen(tstWindow);
					SetWindowFullscreen(canvasWindow);
					SetWindowFullscreen(coverWindow);
					fullscreen = TRUE;
					printf("[+] Windows set to fullscreen\n");
				}


			}
		}
	}
	return CallNextHookEx(hkeyboardhook, nCode, wParam, lParam);
}

DWORD WINAPI KeyboardHookThread(LPVOID lpParameter)
{
	HINSTANCE hInstance = GetModuleHandle(NULL);
	hkeyboardhook = SetWindowsHookEx(WH_KEYBOARD_LL, KeyboardProc, hInstance, 0);
	MSG msg;
	while (GetMessage(&msg, NULL, 0, 0))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
	UnhookWindowsHookEx(hkeyboardhook);
	return 0;
}



DWORD WINAPI HackThread(HMODULE hModule)
{
#ifdef DEBUG
	AllocConsole();
	FILE* f;
	freopen_s(&f, "CONOUT$", "w", stdout);
	printf("[~] hi\n");
#endif


	HMODULE hModule2 = RemoveModuleFromPEB(L"DLL.dll");

	HMODULE hModule3 = RemoveModuleFromPEB(L"DLL.dll");
	if (hModule3 == NULL)
	{
#ifdef DEBUG
		printf("[+] DLL not found, SUCCESS!\n");
#endif // DEBUG


	}
	else
	{
#ifdef DEBUG
		printf("[!] DLL found, FAILURE!\n");
#endif // DEBUG
	}

	ogGetForegroundWindow = (tGetForegroundWindow)GetProcAddress(GetModuleHandle(L"user32.dll"), "GetForegroundWindow");
	ogGetForegroundWindow = (tGetForegroundWindow)mem::TrampHook32((BYTE*)ogGetForegroundWindow, (BYTE*)hkGetForegroundWindow, 5);
	
	ogTerminateProcess = (tTerminateProcess)GetProcAddress(GetModuleHandle(L"Kernel32.dll"), "TerminateProcess");
	ogTerminateProcess = (tTerminateProcess)mem::TrampHook32((BYTE*)ogTerminateProcess, (BYTE*)hkTerminateProcess, 5);
	
	originalGetDesktopWindow = (tGetDesktopWindow)GetProcAddress(GetModuleHandle(L"user32.dll"), "GetDesktopWindow");
	originalGetDesktopWindow = (tGetDesktopWindow)mem::TrampHook32((BYTE*)originalGetDesktopWindow, (BYTE*)hkGetDesktopWindow, 5);
	

	ogEmptyClipboard = (tEmptyClipboard)GetProcAddress(GetModuleHandle(L"user32.dll"), "EmptyClipboard");
	ogEmptyClipboard = (tEmptyClipboard)mem::TrampHook32((BYTE*)ogEmptyClipboard, (BYTE*)hkEmptyClipboard, 5);

	ogMessageBoxA = (tMessageBoxA)GetProcAddress(GetModuleHandle(L"user32.dll"), "MessageBoxA");
	ogMessageBoxA = (tMessageBoxA)mem::TrampHook32((BYTE*)ogMessageBoxA, (BYTE*)hkMessageBoxA, 5);

	HANDLE hThread = CreateThread(NULL, 0, KeyboardHookThread, NULL, 0, NULL);
	if (hThread != NULL)
	{
		CloseHandle(hThread);
	}

	//ogNtQuerySystemInformation = (PNT_QUERY_SYSTEM_INFORMATION)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQuerySystemInformation");
	//ogNtQuerySystemInformation = (PNT_QUERY_SYSTEM_INFORMATION)mem::TrampHook32((BYTE*)ogNtQuerySystemInformation, (BYTE*)HookedNtQuerySystemInformation, 5);

	


	return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		CloseHandle(CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)HackThread, hModule, 0, nullptr));
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
