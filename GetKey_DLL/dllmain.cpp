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

int locale, version, subversion, prollyTest;

uchar* SeekAoB(int startAddr, uchar *aob, int aobLen) {
	uchar* currentAddress = (uchar*)startAddr;
	int i = 0;
	for (; i < 0x01000000; i++) {
		bool found = true;
		for (int j = 0; j < aobLen; j++) {
			if (aob[j] == (uchar)0xFF) continue;
			if (currentAddress[j] != aob[j]) {
				found = false;
				break;
			}

		}

		if (found) return currentAddress;

		currentAddress++;
	}

	return 0;
}

void ShowAESKey(uchar* location) {
	int* aesKeyLocation = (int*)location;
	char* buffer = new char[100];
	sprintf_s(buffer, 100, "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
		aesKeyLocation[0], aesKeyLocation[1], aesKeyLocation[2], aesKeyLocation[3], aesKeyLocation[4], aesKeyLocation[5], aesKeyLocation[6], aesKeyLocation[7],
		aesKeyLocation[8], aesKeyLocation[9], aesKeyLocation[10], aesKeyLocation[11], aesKeyLocation[12], aesKeyLocation[13], aesKeyLocation[14], aesKeyLocation[15],
		aesKeyLocation[16], aesKeyLocation[17], aesKeyLocation[18], aesKeyLocation[19], aesKeyLocation[20], aesKeyLocation[21], aesKeyLocation[22], aesKeyLocation[23],
		aesKeyLocation[24], aesKeyLocation[25], aesKeyLocation[26], aesKeyLocation[27], aesKeyLocation[28], aesKeyLocation[29], aesKeyLocation[30], aesKeyLocation[31]
		);

	char* title = new char[100];
	sprintf_s(title, 100, "KEYZ HERE (Locale %d Version %d Subversion %d unk %d)", locale, version, subversion, prollyTest);
	MessageBoxA(NULL, buffer, title, MB_OK);
	delete[] buffer;
	delete[] title;
}

void ShowCloseWindow() {
	if (MessageBoxA(NULL, "Terminate Maple?", NULL, MB_YESNO) == IDYES) {
		TerminateProcess(GetCurrentProcess(), 0);
	}
}

uchar* FindOriginalAESKey() {
	uchar *aob = new uchar[8]{
		0x13, 0x00, 0x00, 0x00, 0x52, 0x00, 0x00, 0x00
	};
	return SeekAoB(0x01000000, aob, 8);
}

uchar* FindChangedAESKey() {
	uchar *aob = new uchar[8]{
		0xEC, 0x3F, 0x77, 0xA4, 0x45, 0xD0, 0x71, 0xBF
	};
	auto result = SeekAoB(0x01000000, aob, 8);
	if ((int)result > AES_KEY_LENGTH) {
		result -= AES_KEY_LENGTH;
	}

	return result;
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
					MessageBoxA(NULL, buffer, "GetKey_DLL", MB_OK);
					delete[] buffer;
					break;
				}
				default:
				{

					char* buffer = new char[100];
					sprintf_s(buffer, 100, "Unsupported locale! Version %d.%d locale %d. Still want to try, tho?", version, subversion, locale);
					bool doContinue = MessageBoxA(NULL, buffer, "GetKey_DLL", MB_YESNO) == IDYES;
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

	uchar* originalKey = FindOriginalAESKey();

	if (originalKey == 0) {
		originalKey = FindChangedAESKey();
		if (originalKey != 0) {
			ShowAESKey(originalKey);
			ShowCloseWindow();
			return;
		}
	}
	else {
		char* buffer = new char[100];
		sprintf_s(buffer, 100, "Original userkey is at %08X. Checking for Keychanger bytes", originalKey);
		MessageBoxA(NULL, buffer, "GetKey_DLL", MB_OK);
		delete[] buffer;
	}

	uchar* address = SeekAoB(0x00400000, ArrayOfBytes, AOB_LENGTH);
	if (address == 0) {

		address = SeekAoB(0x00400000, ArrayOfBytesTWMS, AOB_LENGTH_TWMS);
		if (address == 0) {
			MessageBoxA(NULL, "The keychanger was not found. (tried KMS/GMS and TWMS)", "GetKey_DLL", MB_OK);
		}
	}

	if (address != 0) {
		{
			char* buffer = new char[100];
			sprintf_s(buffer, 100, "CAESCipher::Encrypt is at %08X", address);
			MessageBoxA(NULL, buffer, "GetKey_DLL", MB_OK);
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
