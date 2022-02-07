
#include <iostream>
#include <windows.h>

enum AMD_RC2_ERROR_CODE {
	AMD_RC2_uninitial,
	AMD_RC2_loaded,
	AMD_RC2_unloaded,
	AMD_RC2_failed_signature,
	AMD_RC2_driver_not_found,
	AMD_RC2_cannot_open,
	AMD_RC2_failed_memory_alloc,
	AMD_RC2_offset_overflow,
	AMD_RC2_driver_version_old,
	AMD_RC2_not_admin,
	AMD_RC2_name_failed,
};

typedef struct {
	UINT uStructSize;
	UINT uStructVersion;
	UINT uDiskNum;
	int iPhysicalDrive;
	UINT64 uDriveSize64;
	DWORD uDriveSize;
	BYTE isSSD;
	BYTE isNVMe;
	BYTE reserved1;
	BYTE reserved2;
	char sModel[41];
	char sSerialNumber[21];
	char sFirmwareRev[9];
	char sSpeed[60];
	BYTE reserved3[93];
} AMD_RC2_IDENTIFY;


typedef UINT(__stdcall* A_AMD_RC2_UINT)();
A_AMD_RC2_UINT AMD_RC2_Init = NULL;
A_AMD_RC2_UINT AMD_RC2_GetStatus = NULL;
A_AMD_RC2_UINT AMD_RC2_GetDrives = NULL;
A_AMD_RC2_UINT AMD_RC2_Reload = NULL;

typedef BOOL(__stdcall* A_AMD_RC2_GetIdentify)(AMD_RC2_IDENTIFY* st_id);
A_AMD_RC2_GetIdentify AMD_RC2_GetIdentify = NULL;

typedef BOOL(__stdcall* A_AMD_RC2_GetSmartData)(int diskNum, BYTE* SmartReadData, int SmartReadDataLen, BYTE* SmartReadThreshold, int SmartReadThresholdLen);
A_AMD_RC2_GetSmartData AMD_RC2_GetSmartData = NULL;


#include <Softpub.h>
#pragma comment(lib, "Wintrust.lib")
#pragma comment(lib, "Crypt32.lib")

#include <setupapi.h>
#pragma    comment(lib,"setupapi.lib")

// ret: -1 = error, 0 = not found, 1 = version lesser, 2 = ready
int AMD_RaidCheck()
{
	int ret = 0;
	HDEVINFO hDevInfo = SetupDiGetClassDevsW(NULL, 0, 0, DIGCF_PRESENT | DIGCF_ALLCLASSES);
	if (hDevInfo == INVALID_HANDLE_VALUE) return -1;

	SP_DEVINFO_DATA    sDevInfo = { sizeof(SP_DEVINFO_DATA) };
	DWORD dwIndex = 0;
	while (dwIndex != 0xFFFFFFFF && SetupDiEnumDeviceInfo(hDevInfo, dwIndex++, &sDevInfo))
	{
		wchar_t pszName[200] = {};
		DWORD dwSize = 200;
		DWORD dwRegType = 0;
		if (!SetupDiGetDeviceRegistryPropertyW(hDevInfo, &sDevInfo, SPDRP_DEVICEDESC, &dwRegType, (BYTE*)pszName, dwSize, &dwSize))
		{
			continue;
		}
		if (wcsstr(pszName, L"AMD-RAID Config") && SetupDiBuildDriverInfoList(hDevInfo, &sDevInfo, SPDIT_COMPATDRIVER)) {
			for (int j = 0; ; ++j)
			{
				SP_DRVINFO_DATA drvInfo = { sizeof(SP_DRVINFO_DATA) };
				if (!SetupDiEnumDriverInfoW(hDevInfo, &sDevInfo, SPDIT_COMPATDRIVER, j, &drvInfo))
					break;

				if (wcsstr(drvInfo.ProviderName, L"Advanced Micro Devices")) {
					/*wprintf(L"%s %d.%d.%d.%d\n", pszName, (USHORT)(drvInfo.DriverVersion >> 48),
						(USHORT)(drvInfo.DriverVersion >> 32),
						(USHORT)(drvInfo.DriverVersion >> 16),
						(USHORT)(drvInfo.DriverVersion));*/
					constexpr UINT64 AMD_RC2_min_version = ((9ULL << 48) | (3ULL << 32) | (0ULL << 16) | 266ULL);//9.3.0.266
					ret = drvInfo.DriverVersion >= AMD_RC2_min_version ? 2 : 1;
					dwIndex = 0xFFFFFFFF;
					break;
				}
			}
		}
	}
	SetupDiDestroyDeviceInfoList(hDevInfo);
	return ret;
}


bool DigitalSignatureCheck(wchar_t* path) {
	WINTRUST_FILE_INFO FileData = { sizeof(WINTRUST_FILE_INFO) };
	FileData.pcwszFilePath = path;

	GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
	WINTRUST_DATA WinTrustData = { sizeof(WinTrustData) };
	WinTrustData.dwUIChoice = WTD_UI_NONE;
	WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
	WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;
	WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
	WinTrustData.pFile = &FileData;

	bool cert_chk = false;
	if (WinVerifyTrust(NULL, &WVTPolicyGUID, &WinTrustData) == ERROR_SUCCESS) {
		CRYPT_PROVIDER_DATA const* psProvData = NULL;
		CRYPT_PROVIDER_SGNR* psProvSigner = NULL;
		CRYPT_PROVIDER_CERT* psProvCert = NULL;

		psProvData = WTHelperProvDataFromStateData(WinTrustData.hWVTStateData);
		if (psProvData) {
			psProvSigner = WTHelperGetProvSignerFromChain((PCRYPT_PROVIDER_DATA)psProvData, 0, FALSE, 0);
			if (psProvSigner) {
				psProvCert = WTHelperGetProvCertFromChain(psProvSigner, 0);
				if (psProvCert) {
					wchar_t szCertName[200] = {};
					DWORD dwStrType = CERT_X500_NAME_STR;
					CertGetNameStringW(psProvCert->pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, &dwStrType, szCertName, 200);
					cert_chk = (szCertName[0] != '\0' && wcscmp(szCertName, L"Gakuto Matsumura") == 0);
				}
			}
		}
	}
	WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
	(void)WinVerifyTrust(NULL, &WVTPolicyGUID, &WinTrustData);
	return cert_chk;
}


int main()
{
	const int check1 = AMD_RaidCheck();
	if (check1 <= 0) {
		std::cout << "! AMD-RAID Not Found\n";
		(void)getchar();
		return 0;
	}
	else if (check1 <= 1) {
		std::cout << "! AMD-RAID Version is Lesser\n";
		(void)getchar();
		return 0;
	}

	wchar_t	buffer1[261] = {}, dir1[261] = {}, buffer3[261] = {};

	GetModuleFileNameW(NULL, buffer1, 261);
	_wsplitpath_s(buffer1, dir1, 261, buffer3, 261, NULL, 0, NULL, 0);
	wcscat_s(dir1, 261, buffer3);

	wcscpy_s(buffer1, 261, dir1);
#ifdef _M_AMD64
	wcscat_s(buffer1, 261, L"AMD_RC2t7x64.dll");
#else
	wcscat_s(buffer1, 261, L"AMD_RC2t7x86.dll");
#endif

	if (!DigitalSignatureCheck(buffer1)) {
		std::cout << "! Check Digital Signature\n";
		(void)getchar();
		return FALSE;
	}

	// DLL load

	const HMODULE dll__AMD_RC2 = LoadLibraryW(buffer1);
	if (!dll__AMD_RC2) {
		std::cout << "! DLL load\n";
		(void)getchar();
		return 0;
	}
	std::cout << "DLL load\n";
	AMD_RC2_Init = (A_AMD_RC2_UINT)GetProcAddress(dll__AMD_RC2, "AMD_RC2_Init");
	AMD_RC2_GetStatus = (A_AMD_RC2_UINT)GetProcAddress(dll__AMD_RC2, "AMD_RC2_GetStatus");
	AMD_RC2_GetDrives = (A_AMD_RC2_UINT)GetProcAddress(dll__AMD_RC2, "AMD_RC2_GetDrives");
	AMD_RC2_Reload = (A_AMD_RC2_UINT)GetProcAddress(dll__AMD_RC2, "AMD_RC2_Reload");
	AMD_RC2_GetIdentify = (A_AMD_RC2_GetIdentify)GetProcAddress(dll__AMD_RC2, "AMD_RC2_GetIdentify");
	AMD_RC2_GetSmartData = (A_AMD_RC2_GetSmartData)GetProcAddress(dll__AMD_RC2, "AMD_RC2_GetSmartData");
	if (!AMD_RC2_Init || !AMD_RC2_GetStatus || !AMD_RC2_GetDrives || !AMD_RC2_Reload || !AMD_RC2_GetIdentify || !AMD_RC2_GetSmartData) {
		std::cout << "! DLL function\n";
		(void)getchar();
		return 0;
	}
	UINT status = AMD_RC2_Init();
	std::cout << "DLL function: " << status << "\n";

	if (status == 1) {
		// get smart
		int drives = AMD_RC2_GetDrives() - 1;
		std::cout << "Drives: " << drives << "\n";

		for (int drive = 0; drive < drives; ++drive) {
			AMD_RC2_IDENTIFY st_id = { sizeof(AMD_RC2_IDENTIFY), 1 };
			st_id.uDiskNum = drive;

			if (!AMD_RC2_GetIdentify(&st_id)) continue;
			std::cout << "num:" << 0 << "phy: " << st_id.iPhysicalDrive << " model: " << st_id.sModel << " serial: " << st_id.sSerialNumber << " firm: " << st_id.sFirmwareRev << " speed: " << st_id.sSpeed << " drive_size: " << st_id.uDriveSize << "\n";

			BYTE SmartReadData[512] = {}, SmartReadThreshold[512] = {};
			AMD_RC2_GetSmartData(drive, SmartReadData, 512, SmartReadThreshold, 512);
			std::cout << "SmartData ";
			for (int i = 0; i < 32; ++i) std::cout << (int)SmartReadData[i] << " ";
			std::cout << " ...\n";
		}
	}
	(void)getchar();
	return 1;
}
