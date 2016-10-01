#pragma comment(lib,"Version.lib")
#include "stdafx.h"
#include <stdio.h>

#define uchar unsigned char

#define AES_KEY_LENGTH (4 * 4 * 8)

// IDA AoB: 81 EC 3C 01 00 00 A1 ? ? ? 01 33 C4 89 84 24 38 01 00 00 
#define AOB_LENGTH 20
uchar* ArrayOfBytes = new uchar[AOB_LENGTH]{
	0x81, 0xEC, 0x3C, 0x01, 0x00, 0x00,			// sub esp, 13Ch
	0xA1, 0xFF, 0xFF, 0xFF, 0xFF,				// mov eax, something
	0x33, 0xC4,									// xor eax, esp
	0x89, 0x84, 0x24, 0x38, 0x01, 0x00, 0x00	// mov [esp+13Ch-4], eax
};

// IDA AoB: 55 8B EC 81 EC 3C 01 00 00 A1 ? ? ? ? 33 C5
#define AOB_LENGTH_TWMS 16
uchar* ArrayOfBytesTWMS = new uchar[AOB_LENGTH_TWMS]{
	0x55,										// push ebp
	0x8B, 0xEC,									// mob ebp, esp
	0x81, 0xEC, 0x3C, 0x01, 0x00, 0x00,			// sub esp, 13Ch
	0xA1, 0xFF, 0xFF, 0xFF, 0xFF,				// mov eax, something
	0x33, 0xC5,									// xor eax, something
};

// V123.1: 00440E00
// V132.1: 00444B90
// V137.2: 00445C10
// V140.1: 004466A0
// V141.1: 00446560
// V142.1: 00494C00 - such gap. wow. Downveil update; Secondary stat moved 400k bytes down. Different precompiled header?
// V149.2: 0049A9C0


void Run();

typedef void(*CAESCipher_Encrypt)(int, int, size_t, int);
typedef void(*CAESCipher_Encrypt_KOR)(int, int, size_t, int, int pEncrypt);

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
	)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH: Run(); break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

HWND g_hwndTimedOwner;
BOOL g_bTimedOut;

void CALLBACK MessageBoxTimer(HWND hwnd,
	UINT uiMsg,
	UINT idEvent,
	DWORD dwTime)
{
	g_bTimedOut = TRUE;
	if (g_hwndTimedOwner)
		EnableWindow(g_hwndTimedOwner, TRUE);
	PostQuitMessage(0);
}


int TimedMessageBox(HWND hwndOwner,
	LPCSTR pszMessage,
	LPCSTR pszTitle,
	UINT flags,
	DWORD dwTimeout)
{
	flags |= MB_SETFOREGROUND;

	UINT idTimer;
	int iResult;

	g_hwndTimedOwner = NULL;
	g_bTimedOut = FALSE;

	if (hwndOwner && IsWindowEnabled(hwndOwner))
		g_hwndTimedOwner = hwndOwner;

	//
	// Set a timer to dismiss the message box.
	idTimer = SetTimer(NULL, 0, dwTimeout, (TIMERPROC)MessageBoxTimer);

	iResult = MessageBoxA(hwndOwner, pszMessage, pszTitle, flags);

	//
	// Finished with the timer.
	KillTimer(NULL, idTimer);

	//
	// See if there is a WM_QUIT message in the queue if we timed out.
	// Eat the message so we do not quit the whole application.
	if (g_bTimedOut)
	{
		MSG msg;
		PeekMessage(&msg, NULL, WM_QUIT, WM_QUIT, PM_REMOVE);
		DWORD button1 = IDOK, button2 = 0, button3 = 0;
		if (flags & MB_CANCELTRYCONTINUE) {
			button1 = IDCANCEL;
			button2 = IDTRYAGAIN;
			button3 = IDCONTINUE;
		}
		else if (flags & MB_RETRYCANCEL) {
			button1 = IDRETRY;
			button2 = IDCANCEL;
		}
		else if (flags & MB_YESNO) {
			button1 = IDYES;
			button2 = IDNO;
		}
		else if (flags & MB_YESNOCANCEL) {
			button1 = IDYES;
			button2 = IDNO;
			button3 = IDCANCEL;
		}
		else if (flags & MB_ABORTRETRYIGNORE) {
			button1 = IDABORT;
			button2 = IDRETRY;
			button3 = IDIGNORE;
		}
		else if (flags & MB_OKCANCEL) {
			button1 = IDOK;
			button2 = IDCANCEL;
		}

		if (flags & MB_DEFBUTTON2) iResult = button2;
		else if (flags & MB_DEFBUTTON3) iResult = button3;
		iResult = -1;
	}

	return iResult;
}

int locale, version, subversion, prollyTest;

int default_max_offset = 0x01000000;
uchar* SeekAoB(int startAddr, uchar *aob, int aobLen, bool gotoStartOfFunc = false, int maxOffset = default_max_offset) {
	uchar* currentAddress = (uchar*)startAddr;
	int i = 0;

	for (; i < maxOffset; i++) {
		bool found = true;
		for (int j = 0; j < aobLen; j++) {
			if (aob[j] == (uchar)0xFF) continue;
			if (currentAddress[j] != aob[j]) {
				found = false;
				break;
			}

		}

		if (found) {
			if (gotoStartOfFunc) {
				for (; currentAddress[-1] != (uchar)0xCC; currentAddress--);
			}
			return currentAddress;
		}
		currentAddress++;
	}

	return 0;
}

void ShowAESKey(uchar* location) {
	int* aesKeyLocation = (int*)location;
	char* keyBuffer = new char[100];
	sprintf_s(keyBuffer, 100, "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
		aesKeyLocation[0], aesKeyLocation[1], aesKeyLocation[2], aesKeyLocation[3], aesKeyLocation[4], aesKeyLocation[5], aesKeyLocation[6], aesKeyLocation[7],
		aesKeyLocation[8], aesKeyLocation[9], aesKeyLocation[10], aesKeyLocation[11], aesKeyLocation[12], aesKeyLocation[13], aesKeyLocation[14], aesKeyLocation[15],
		aesKeyLocation[16], aesKeyLocation[17], aesKeyLocation[18], aesKeyLocation[19], aesKeyLocation[20], aesKeyLocation[21], aesKeyLocation[22], aesKeyLocation[23],
		aesKeyLocation[24], aesKeyLocation[25], aesKeyLocation[26], aesKeyLocation[27], aesKeyLocation[28], aesKeyLocation[29], aesKeyLocation[30], aesKeyLocation[31]
		);


	char* title = new char[100];
	sprintf_s(title, 100, "KEYZ HERE (Locale %d Version %d Subversion %d unk %d)", locale, version, subversion, prollyTest);

	MessageBoxA(NULL, keyBuffer, title, MB_OK | MB_ICONASTERISK | MB_TOPMOST);
	delete[] keyBuffer;
	delete[] title;
}

void ShowCloseWindow() {
	if (TimedMessageBox(NULL, "Terminate Maple?", "GetKey_DLL", MB_YESNO, 2000) == IDYES) {
		TerminateProcess(GetCurrentProcess(), 0);
	}
}

uchar* FindOriginalAESKey(int startPos = 0x01000000, int maxOffset = default_max_offset) {
	uchar *aob = new uchar[8]{
		0x13, 0x00, 0x00, 0x00, 0x52, 0x00, 0x00, 0x00
	};
	return SeekAoB(startPos, aob, 8, false, maxOffset);
}

uchar* FindChangedAESKey(int startPos = 0x01000000, int maxOffset = default_max_offset) {
	uchar *aob = new uchar[8]{
		0xEC, 0x3F, 0x77, 0xA4, 0x45, 0xD0, 0x71, 0xBF
	};
	auto result = SeekAoB(startPos, aob, 8, false, maxOffset);
	if ((int)result > AES_KEY_LENGTH) {
		result -= AES_KEY_LENGTH;
	}

	return result;
}

uchar* FindChangeAESKeyZLZ(int libPos) {
	uchar *aob = new uchar[9]{
		0x55, 0x8B, 0xEC, 0x81, 0xEC, 0x80, 0x00, 0x00, 0x00
	};
	auto funcPos = SeekAoB(libPos, aob, 9, true, 0x0020000);
	if (funcPos == 0) {
		aob = new uchar[6]{
			0x81, 0xEC, 0x80, 0x00, 0x00, 0x00
		};
		funcPos = SeekAoB(libPos, aob, 6, true, 0x0020000);
	}

	return funcPos;
}

void FindAESKeyThroughZLZ() {
	HMODULE mod = LoadLibraryA("ZLZ.dll");

	int addr = (int)mod;

	auto changeKeyPos = FindChangeAESKeyZLZ(addr);
	if (changeKeyPos == 0) {
		TimedMessageBox(NULL, "The keychanger was not found in ZLZ.dll....?!", "GetKey_DLL", MB_OK, 2000);
		FreeLibrary(mod);
		ShowCloseWindow();
		return;
	}
	else {
		char* buffer = new char[100];
		sprintf_s(buffer, 100, "Keychanger is at %08X", changeKeyPos);
		TimedMessageBox(NULL, buffer, "GetKey_DLL", MB_OK, 3000);
		delete[] buffer;
	}

	auto aesKeyPos = FindOriginalAESKey(addr);
	if (aesKeyPos == 0) {
		TimedMessageBox(NULL, "The AES key was not found in ZLZ.dll....?!", "GetKey_DLL", MB_OK, 2000);
		FreeLibrary(mod);
		ShowCloseWindow();
		return;
	}
	else {
		char* buffer = new char[100];
		sprintf_s(buffer, 100, "AES key is at %08X", aesKeyPos);
		TimedMessageBox(NULL, buffer, "GetKey_DLL", MB_OK, 3000);
		delete[] buffer;
	}

	ShowAESKey(aesKeyPos);

	void(*CAES__ChangeKey)(void) = (void(*)(void))(changeKeyPos);

	TimedMessageBox(NULL, "Changing key...", "GetKey_DLL", MB_OK, 1000);
	CAES__ChangeKey();

	TimedMessageBox(NULL, "Showing key...", "GetKey_DLL", MB_OK, 1000);
	ShowAESKey(aesKeyPos);


	FreeLibrary(mod);
}

DWORD WINAPI DetectChangedAESKey(LPVOID lpParam) {
	uchar* originalKey = (uchar*)lpParam;
	while (originalKey[0] == 0x13) Sleep(100);

	ShowAESKey(originalKey);
	ShowCloseWindow();
	return 0;
}

void Run() {

	// Check what kind of exe we have here
	char* exeName = new char[MAX_PATH];
	GetModuleFileNameA(0, exeName, MAX_PATH);
	DWORD verHandle = NULL;
	UINT size = 0;
	LPBYTE lpBuffer = NULL;
	DWORD verSize = 0;

	bool isKms = false;

	if ((verSize = GetFileVersionInfoSizeA(exeName, &verHandle)) != NULL) {
		LPSTR verData = new char[verSize];
		if (GetFileVersionInfoA(exeName, verHandle, verSize, verData) &&
			VerQueryValueA(verData, "\\", (VOID FAR* FAR*)&lpBuffer, &size) && size)
		{
			VS_FIXEDFILEINFO *verInfo = (VS_FIXEDFILEINFO *)lpBuffer;
			if (verInfo->dwSignature == 0xfeef04bd)
			{
				locale = HIWORD(verInfo->dwFileVersionMS);
				version = LOWORD(verInfo->dwFileVersionMS);
				subversion = HIWORD(verInfo->dwFileVersionLS);
				prollyTest = LOWORD(verInfo->dwFileVersionLS);

				if (locale == 1 && version == 0 && subversion == 0 && prollyTest == 1) {
					MessageBoxA(NULL, "Unsupported version (very old?)!", "GetKey_DLL", MB_OK);
					return;
				}

				switch (locale) {
				case 1:
				case 8:
				{

					char* buffer = new char[100];
					sprintf_s(buffer, 100, "Executable version %d.%d locale %d", version, subversion, locale);
					TimedMessageBox(NULL, buffer, "GetKey_DLL", MB_OK, 1000);
					delete[] buffer;
					break;
				}
				default:
				{

					char* buffer = new char[100];
					sprintf_s(buffer, 100, "Unsupported locale! Version %d.%d locale %d. Still want to try, tho?", version, subversion, locale);
					bool doContinue = TimedMessageBox(NULL, buffer, "GetKey_DLL", MB_YESNO, 2000) == IDYES;
					delete[] buffer;

					if (doContinue)
						break;
					else
						return;
				}
				}

				isKms = locale == 1;

			}
		}
		delete[] verData;
	}

	auto response = TimedMessageBox(NULL, "Get key from ZLZ.dll?", "GetKey_DLL", MB_YESNO | MB_ICONASTERISK | MB_DEFBUTTON2, 2000);
	if (response == IDYES) {
		FindAESKeyThroughZLZ();
	}

	int startPos = 0x01000000;

	response = TimedMessageBox(NULL, "Try expanded search region (big clients)?", "GetKey_DLL", MB_YESNO | MB_ICONASTERISK, 3000);
	if (response == IDYES) {
		startPos = 0x02000000;
		default_max_offset *= 5;
	}

	uchar* originalKey = FindOriginalAESKey(startPos);

	if (originalKey == 0) {
		TimedMessageBox(NULL, "Original key not found. Checking for changed key.", "GetKey_DLL", MB_OK | MB_ICONERROR, 1500);

		originalKey = FindChangedAESKey(startPos);
		if (originalKey != 0) {
			ShowAESKey(originalKey);
			ShowCloseWindow();
			return;
		}
		else {
			TimedMessageBox(NULL, "Not found.", "GetKey_DLL", MB_OK | MB_ICONERROR, 1500);
		}
	}
	else {
		TimedMessageBox(NULL, "Found. Waiting for it to change...", "GetKey_DLL", MB_OK | MB_ICONINFORMATION, 1500);
		CreateThread(
			NULL,
			0,
			DetectChangedAESKey,
			originalKey,
			0,
			NULL);
		return;
	}

	uchar* address = SeekAoB(0x00400000, ArrayOfBytes, AOB_LENGTH);
	if (address == 0) {

		address = SeekAoB(0x00400000, ArrayOfBytesTWMS, AOB_LENGTH_TWMS);
		if (address == 0) {
			MessageBoxA(NULL, "The keychanger was not found. (tried KMS/GMS and TWMS).", "GetKey_DLL", MB_OK | MB_ICONEXCLAMATION);
		}
	}

	if (address != 0) {
		{
			char* buffer = new char[100];
			sprintf_s(buffer, 100, "CAESCipher::Encrypt is at %08X", address);
			TimedMessageBox(NULL, buffer, "GetKey_DLL", MB_OK, 1500);
			delete[] buffer;
		}

		if (isKms) {
			((CAESCipher_Encrypt_KOR)address)(0, 0, 0, 0, 1);
		}
		else {
			((CAESCipher_Encrypt)address)(0, 0, 0, 0);
		}

		ShowAESKey(originalKey);
	}

	ShowCloseWindow();
}
