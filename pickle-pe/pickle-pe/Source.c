#include <Windows.h>
#include <WinBase.h>
#include <stdio.h>
#include <stdlib.h>
#include <errhandlingapi.h>
#include <winnt.h>
#include <fileapi.h>
#include <time.h>
#include <wincrypt.h>
#include <string.h>
#include <heapapi.h>
#include <timezoneapi.h>
#include <Softpub.h>
#include <wintrust.h>

#include "Header.h"

int __cdecl main(int argc, const char* argv[])
{
	enter();
	if (argc < 2)
	{
		printf_s("Usage : pickle-pe.exe --help\n");
		//system(pause);
		return 0x0;
	}

	int i = 1, control = 0;
	const char* param = argv[1];


	for (i = 1; i < argc; i++)
	{
		param = argv[i];
		if (i == 1)
		{
			if (!strcmp(param, HELP) && control == 0)
			{
				help();
			}
			else if (!strcmp(param, VERSION) && control == 0) //exe olup olmadýðýný kontrol et
			{
				version();
			}
			else
			{
				_fileMetadata.fileName = param;
				mapping();
				_peHeader.dosHeader = (PIMAGE_DOS_HEADER)_fileMetadata.hFileBase;
				if (_fileMetadata.hFileMapping == 0x0 || _peHeader.dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
				{
					printf_s("Please, Enter Portable Executable file !\n");
					return 0x0;
				}
				__FILE_METADATA(_fileMetadata.fileName);
				control = 1;
			}
		}

		if (!strcmp(param, DOS_HEADER) && control == 1)
		{
			__DOS_HEADER(_fileMetadata.hFileBase);
		}
		else if (!strcmp(param, NT_HEADER) && control == 1)
		{
			__NT_HEADER(_fileMetadata.hFileBase);
		}
		else if (!strcmp(param, FILE_HEADER) && control == 1)
		{
			__FILE_HEADER(_fileMetadata.hFileBase);
		}
		else if (!strcmp(param, OPTIONAL_HEADER) && control == 1)
		{
			__OPTIONAL_HEADER(_fileMetadata.hFileBase);
		}
		else if (!strcmp(param, DATA_DIRECTORY) && control == 1)
		{
			__DATA_DIRECTORY(_fileMetadata.hFileBase);
		}
		else if (!strcmp(param, SECTION_HEADER) && control == 1)
		{
			__IMAGE_FILE_HEADER(_fileMetadata.hFileBase);
		}
		else if (!strcmp(param, IMPORT_DIRECTORY) && control == 1)
		{
			__IMPORT_DIRECTORY();
		}
		else if (!strcmp(param, HEXDUMP) && control == 1)
		{
			hexdump();
		}
		else if (!strcmp(param, STRINGS) && control == 1)
		{
			_strings();
		}
	}

	return 0x0;
}

void mapping()
{
	LPCSTR fileName = _fileMetadata.fileName;
	_fileMetadata.hFile = CreateFileA((LPCSTR)fileName, (DWORD)GENERIC_READ, (DWORD)FILE_SHARE_READ, (LPSECURITY_ATTRIBUTES)NULL, (DWORD)OPEN_EXISTING, (DWORD)FILE_ATTRIBUTE_NORMAL, (HANDLE)NULL);

	if (_fileMetadata.hFile == INVALID_HANDLE_VALUE)
	{
		//printf_s("%10d", GetLastError());
	}

	_fileMetadata.hFileMapping = CreateFileMappingA((LPVOID)_fileMetadata.hFile, (LPSECURITY_ATTRIBUTES)NULL, (DWORD)PAGE_READONLY, (DWORD)0, (DWORD)0, NULL);

	if (_fileMetadata.hFileMapping == NULL)
	{
		//printf_s("%10d", GetLastError());
		CloseHandle(_fileMetadata.hFile);
	}

	_fileMetadata.hFileBase = MapViewOfFile((LPVOID)_fileMetadata.hFileMapping, (DWORD)FILE_MAP_READ, (DWORD)0, (DWORD)0, (SIZE_T)0);

	if (_fileMetadata.hFileBase == 0)
	{
		//printf_s("%d", GetLastError());
		CloseHandle(_fileMetadata.hFileMapping);
		CloseHandle(_fileMetadata.hFile);
	}
}

void __FILE_METADATA()
{
	LPCSTR fileName = _fileMetadata.fileName;
	ALG_ID md5 = CALG_MD5;
	ALG_ID sha1 = CALG_SHA1;

	printf_s("[*] File Name : %s\n", fileName);
	mapping(fileName);

	_fileMetadata.dwFileSize = GetFileSize(_fileMetadata.hFile, NULL);

	printf_s("[*] Size : %d bytes\n", _fileMetadata.dwFileSize);

	fileTimeConvert(_fileMetadata.hFile);
	_getHashFile(_fileMetadata.hFile, _md5, MD5LEN, md5);

	_peHeader.dosHeader = (PIMAGE_DOS_HEADER)_fileMetadata.hFileBase;

	if (_peHeader.dosHeader == NULL)
	{
		printf_s("%d\n", GetLastError());
	}

	if (_peHeader.dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf_s("%d\n", GetLastError());
	}
	printf_s("[*] Magic Number : 0X%x\n", _peHeader.dosHeader->e_magic);
	printf_s("[*] Checksum : %d\n", _peHeader.dosHeader->e_csum);

	_peHeader.optionalHeader = (PIMAGE_OPTIONAL_HEADER)OPTHDROFFSET(_fileMetadata.hFileBase);

	printf_s("[*] Entry Point Address : 0x%X\n", _peHeader.optionalHeader->AddressOfEntryPoint);

	_peHeader.fileHeader = (PIMAGE_FILE_HEADER)PEFHDROFFSET(_fileMetadata.hFileBase);
	if (_peHeader.fileHeader->Machine == IMAGE_FILE_MACHINE_I386)
	{
		printf_s("[*] File Type : Portable Executable 32 bit binary \n");
	}
	else if (_peHeader.fileHeader->Machine == IMAGE_FILE_MACHINE_AMD64)
	{
		printf_s("[*] File Type : Portable Executable 64 bit binary \n");
	}
	else if (_peHeader.fileHeader->Machine == IMAGE_FILE_MACHINE_IA64)
	{
		printf_s("[*] File Type : Portable Executable Intel Itanium\n");
	}
	timeConvert(_peHeader.fileHeader->TimeDateStamp);
}

void enter()
{
	printf_s("%s\n", logo);
	printf_s("_______________________________________________________________________\n\n\n");
}
void help()
{
	printf_s("Usage : pickle-pe.exe <file name> -parameter\n\n");

	printf_s("-fi --File Information\n");
	printf_s("-sh --Section Header\n");
	printf_s("-ih --Image File Header\n");
	printf_s("-dh --Dos Header\n");
	printf_s("-nt --NT Header\n");
	printf_s("-oh --Optional Header\n");
	printf_s("-dd --Data Directory\n");
	printf_s("-id --Import Directory\n");
	printf_s("-h --Hex Dump\n");
	printf_s("-s --Strings\n\n");

	printf_s("--help\n");
	printf_s("--version\n\n");

}

void version()
{
	printf_s("Version 1.0 made by ereborlugimli\n\n");
}
void _getHashFile(HANDLE _hFile, const char _hash[], int _len, ALG_ID _alg)
{
	_peHash.hProv = 0;
	_peHash.hHash = 0;
	_peHash.cbHash = 0;
	_peHash.cbRead = 0;
	BOOL result = FALSE;
	strncpy(_peHash.rgbDigits, "0123456789abcdef", 16);


	if (!CryptAcquireContextA(&_peHash.hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) // PROV_RSA_AES
	{
		printf_s("%d", GetLastError());
		CloseHandle(_hFile);
	}

	if (!CryptCreateHash(_peHash.hProv, _alg, 0, 0, &_peHash.hHash))
	{
		printf_s("%d", GetLastError());
		CloseHandle(_hFile);
		CryptReleaseContext(_peHash.hProv, 0);
	}

	while (result = ReadFile(_hFile, _peHash.rgbFile, BUF_SIZE, &_peHash.cbRead, NULL))
	{
		if (_peHash.cbRead == 0)
		{
			break;
		}

		if (!CryptHashData(_peHash.hHash, _peHash.rgbFile, _peHash.cbRead, 0))
		{
			printf_s("%d", GetLastError());
			CryptReleaseContext(_peHash.hProv, 0);
			CryptDestroyHash(_peHash.hHash);
			CloseHandle(_hFile);
		}

	}

	if (!result)
	{
		printf_s("%d", GetLastError());
		CryptReleaseContext(_peHash.hProv, 0);
		CryptDestroyHash(_peHash.hHash);
		CloseHandle(_hFile);
	}

	_peHash.cbHash = _len;

	if (CryptGetHashParam(_peHash.hHash, HP_HASHVAL, _peHash.rgbHash, &_peHash.cbHash, 0))
	{
		printf_s("[*] %s : ", _hash);
		for (DWORD i = 0; i < _peHash.cbHash; i++)
		{
			printf("%c%c", _peHash.rgbDigits[_peHash.rgbHash[i] >> 4], _peHash.rgbDigits[_peHash.rgbHash[i] & 0xf]);
		}
		printf_s("\n");
	}
	else {
		printf_s("%d", GetLastError());
	}
	CryptDestroyHash(_peHash.hHash);
	CryptReleaseContext(_peHash.hProv, 0);
	CloseHandle(_hFile);
}


void fileTimeConvert(HANDLE _hFile)
{
	FILETIME ftCreate, ftAccess, ftWrite;
	SYSTEMTIME stUTC, stLocal;

	if (!GetFileTime(_hFile, &ftCreate, &ftAccess, &ftWrite))
	{
		printf_s("%d", GetLastError());
	}

	FileTimeToSystemTime(&ftCreate, &stUTC);
	SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal);

	printf_s("[*] Creation Time : %02d/%02d/%d %d:%d:%d\n", stLocal.wDay, stLocal.wMonth, stLocal.wYear, stLocal.wHour, stLocal.wMinute, stLocal.wMilliseconds);

	FileTimeToSystemTime(&ftAccess, &stUTC);
	SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal);

	printf_s("[*] Access Time : %02d/%02d/%d %d:%d:%d\n", stLocal.wDay, stLocal.wMonth, stLocal.wYear, stLocal.wHour, stLocal.wMinute, stLocal.wMilliseconds);

	FileTimeToSystemTime(&ftWrite, &stUTC);
	SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal);

	printf_s("[*] Write Time : %02d/%02d/%d %d:%d:%d\n", stLocal.wDay, stLocal.wMonth, stLocal.wYear, stLocal.wHour, stLocal.wMinute, stLocal.wMilliseconds);

}


void __IMAGE_FILE_HEADER(HANDLE _hFileBase)
{
	_peHeader.ntHeader = (PIMAGE_NT_HEADERS)NTSIGNATURE(_hFileBase);
	_peHeader.sectionHeader = (PIMAGE_SECTION_HEADER)SECHDROFFSET(_hFileBase);

	int i = 0;

	printf_s("\n\n[ Section Header ]\n\n");

	for (i = 0; i < 9; i++)
	{
		printf_s("[%s]  ", typeName[i]);
	}
	printf_s("\n\n");
	for (i = 0; i < _peHeader.ntHeader->FileHeader.NumberOfSections; i++)
	{
		printf_s("%5s\t0x%x\t\t0x%x\t\t0x%x\t\t0x%x\t\t0x%x\t\t0x%x\t\t0x%x\t\t    0x%x\n", _peHeader.sectionHeader->Name, _peHeader.sectionHeader->Misc.VirtualSize, _peHeader.sectionHeader->VirtualAddress, _peHeader.sectionHeader->SizeOfRawData, _peHeader.sectionHeader->PointerToRawData, _peHeader.sectionHeader->PointerToRelocations, _peHeader.sectionHeader->PointerToLinenumbers, _peHeader.sectionHeader->NumberOfRelocations, _peHeader.sectionHeader->NumberOfLinenumbers);

		_peHeader.sectionHeader++;
	}

}


void timeConvert(DWORD _time)
{
	time_t time = _time;
	struct tm ts;
	char  buf[30];

	ts = *localtime(&time);
	strftime(buf, sizeof(buf), "%b %d, %Y; %H:%M:%S\n", &ts);

	printf_s("[*] Timestamp : %s\n", buf);

}

void __DOS_HEADER(HANDLE _hFileBase)
{
	_peHeader.dosHeader = (PIMAGE_DOS_HEADER)_hFileBase;
	char _word[] = "WORD";

	if (_peHeader.dosHeader == NULL)
	{
		printf_s("%d\n", GetLastError());
	}

	printf_s("\n\nName\t\tValue\t\tSize\n\n");
	printf_s("e_magic    : 0x%X\t %12s\n", _peHeader.dosHeader->e_magic, _word);
	printf_s("e_cblp     : 0x%X\t %12s\n", _peHeader.dosHeader->e_cblp, _word);
	printf_s("e_cp       : 0x%X\t %12s\n", _peHeader.dosHeader->e_cp, _word);
	printf_s("e_cparhdr  : 0x%X\t %12s\n", _peHeader.dosHeader->e_cparhdr, _word);
	printf_s("e_crlc     : 0x%X\t %12s\n", _peHeader.dosHeader->e_crlc, _word);
	printf_s("e_cs       : 0x%X\t %12s\n", _peHeader.dosHeader->e_cs, _word);
	printf_s("e_csum     : 0x%X\t %12s\n", _peHeader.dosHeader->e_csum, _word);
	printf_s("e_ip       : 0x%X\t %12s\n", _peHeader.dosHeader->e_ip, _word);
	printf_s("e_lfanew   : 0x%X\t %12s\n", _peHeader.dosHeader->e_lfanew, _word);
	printf_s("e_lfarlc   : 0x%X\t %12s\n", _peHeader.dosHeader->e_lfarlc, _word);
	printf_s("e_maxalloc : 0x%X\t %12s\n", _peHeader.dosHeader->e_maxalloc, _word);
	printf_s("e_oemid    : 0x%X\t %12s\n", _peHeader.dosHeader->e_oemid, _word);
	printf_s("e_oeminfo  : 0x%X\t %12s\n", _peHeader.dosHeader->e_oeminfo, _word);
	printf_s("e_ovno     : 0x%X\t %12s\n", _peHeader.dosHeader->e_ovno, _word);
	printf_s("e_res      : 0x%X\t %12s\n", _peHeader.dosHeader->e_res, _word);
	printf_s("e_res2     : 0x%X\t %12s\n", _peHeader.dosHeader->e_res2, _word);
	printf_s("e_sp       : 0x%X\t %12s\n", _peHeader.dosHeader->e_sp, _word);
	printf_s("e_ss       : 0x%X\t %12s\n", _peHeader.dosHeader->e_ss, _word);

}

void __NT_HEADER(HANDLE _hFileBase)
{
	_peHeader.ntHeader = (PIMAGE_NT_HEADERS)NTSIGNATURE(_hFileBase);
	char _dword[] = "DWORD";

	if (_peHeader.ntHeader == NULL)
	{
		printf_s("%d\n", GetLastError());
	}

	printf_s("\n\nName\t\tValue\t\tSize\n\n");
	printf_s("Signature    : 0x%X\t %12s\n", _peHeader.ntHeader->Signature, _dword);
}

void __FILE_HEADER(HANDLE _hFileBase)
{
	_peHeader.fileHeader = (PIMAGE_FILE_HEADER)PEFHDROFFSET(_hFileBase);
	char _word[] = "WORD";
	char _dword[] = "DWORD";

	if (_peHeader.fileHeader == NULL)
	{
		printf_s("%d\n", GetLastError());
	}

	printf_s("\n\nName\t\t\tValue\t\tSize\n\n");
	printf_s("Machine                : 0x%X\t %15s\n", _peHeader.fileHeader->Machine, _word);
	printf_s("Characteristic         : 0x%X\t %15s\n", _peHeader.fileHeader->Characteristics, _word);
	printf_s("NumbeOfSections        : 0x%X\t %15s\n", _peHeader.fileHeader->NumberOfSections, _word);
	printf_s("NumberOfSymbols        : 0x%X\t %16s\n", _peHeader.fileHeader->NumberOfSymbols, _dword);
	printf_s("PointerToSymbolTable   : 0x%X\t %16s\n", _peHeader.fileHeader->PointerToSymbolTable, _dword);
	printf_s("SizeOfOptionalHeader   : 0x%X\t %15s\n", _peHeader.fileHeader->SizeOfOptionalHeader, _word);
	printf_s("TimeDateStamp          : 0x%X\t %8s\n", _peHeader.fileHeader->TimeDateStamp, _dword);

}

void __OPTIONAL_HEADER(HANDLE _hFileBase)
{
	_peHeader.optionalHeader = (PIMAGE_OPTIONAL_HEADER)OPTHDROFFSET(_hFileBase);
	char _word[] = "WORD";
	char _dword[] = "DWORD";
	char _byte[] = "BYTE";

	if (_peHeader.optionalHeader == NULL)
	{
		printf_s("%d\n", GetLastError());
	}

	printf_s("\n\nName\t\t\t\tValue\t\t\tSize\n\n");
	printf_s("Magic                       :  0x%X\t %15s\n", _peHeader.optionalHeader->Magic, _word);
	printf_s("MajorLinkerVersion          :  0x%X\t %15s\n", _peHeader.optionalHeader->MajorLinkerVersion, _byte);
	printf_s("MinorLinkerVersion	    :  0x%X\t %15s\n", _peHeader.optionalHeader->MinorLinkerVersion, _byte);
	printf_s("AddressOfEntryPoint	    :  0x%X\t %15s\n", _peHeader.optionalHeader->AddressOfEntryPoint, _dword);
	printf_s("BaseOfCode		    :  0x%X\t %15s\n", _peHeader.optionalHeader->BaseOfCode, _dword);
	printf_s("BaseOfData	            :  0x%X\t %15s\n", _peHeader.optionalHeader->BaseOfData, _dword);
	printf_s("CheckSum	            :  0x%X\t %15s\n", _peHeader.optionalHeader->CheckSum, _dword);
	printf_s("FileAlignment		    :  0x%X\t %15s\n", _peHeader.optionalHeader->FileAlignment, _dword);
	printf_s("ImageBase		    :  0x%X\t %15s\n", _peHeader.optionalHeader->ImageBase, _dword);
	printf_s("LoaderFlags		    :  0x%X\t %15s\n", _peHeader.optionalHeader->LoaderFlags, _dword);
	printf_s("MajorOperatingSystemVersion :  0x%X\t %15s\n", _peHeader.optionalHeader->MajorOperatingSystemVersion, _word);
	printf_s("MajorSubsystemVersion       :  0x%X\t %15s\n", _peHeader.optionalHeader->MajorSubsystemVersion, _word);
	printf_s("MinorImageVersion	    :  0x%X\t %15s\n", _peHeader.optionalHeader->MinorImageVersion, _word);
	printf_s("MinorOperatingSystemVersion :  0x%X\t %15s\n", _peHeader.optionalHeader->MinorOperatingSystemVersion, _word);
	printf_s("MinorSubsystemVersion	    :  0x%X\t %15s\n", _peHeader.optionalHeader->MinorSubsystemVersion, _word);
	printf_s("NumberOfRvaAndSizes	    :  0x%X\t %15s\n", _peHeader.optionalHeader->NumberOfRvaAndSizes, _dword);
	printf_s("SectionAlignment	    :  0x%X\t %15s\n", _peHeader.optionalHeader->SectionAlignment, _dword);
	printf_s("SizeOfCode		    :  0x%X\t %15s\n", _peHeader.optionalHeader->SizeOfCode, _dword);
	printf_s("SizeOfHeaders		    :  0x%X\t %15s\n", _peHeader.optionalHeader->SizeOfHeaders, _dword);
	printf_s("SizeOfHeapCommit	    :  0x%X\t %15s\n", _peHeader.optionalHeader->SizeOfHeapCommit, _dword);
	printf_s("SizeOfHeapReserve	    :  0x%X\t %15s\n", _peHeader.optionalHeader->SizeOfHeapReserve, _dword);
	printf_s("SizeOfImage	            :  0x%X\t %15s\n", _peHeader.optionalHeader->SizeOfImage, _dword);
	printf_s("SizeOfInitializedData       :  0x%X\t %15s\n", _peHeader.optionalHeader->SizeOfInitializedData, _dword);
	printf_s("SizeOfStackCommit	    :  0x%X\t %15s\n", _peHeader.optionalHeader->SizeOfStackCommit, _dword);
	printf_s("SizeOfStackReserve          :  0x%X\t %15s\n", _peHeader.optionalHeader->SizeOfStackReserve, _dword);
	printf_s("SizeOfUninitializedData	    :  0x%X\t %15s\n", _peHeader.optionalHeader->SizeOfUninitializedData, _dword);
	printf_s("Subsystem		    :  0x%X\t %15s\n", _peHeader.optionalHeader->Subsystem, _word);
	printf_s("Win32VersionValue	    :  0x%X\t %15s\n", _peHeader.optionalHeader->Win32VersionValue, _dword);

}

void __DATA_DIRECTORY(HANDLE _hFileBase)
{
	_peHeader.dosHeader = (PIMAGE_DOS_HEADER)_hFileBase;
	_peHeader.optionalHeader = (PIMAGE_OPTIONAL_HEADER)OPTHDROFFSET(_hFileBase);
	_peHeader.dataDirectory = &_peHeader.optionalHeader->DataDirectory[0];
	int i = 0;

	printf_s("\n\n\t\tName\t\t\tOffset\t\tVirtual Adress\t\tSize\n\n");

	while (i != 16)
	{
		int dataOffset = _peHeader.dataDirectory;
		int dosOffset = _peHeader.dosHeader;
		int rawOffset = dataOffset - dosOffset;
		printf_s("%32s:\t0x%X\t\t0x%X\t\t0x%X\n", directory[i],rawOffset, _peHeader.dataDirectory->VirtualAddress, _peHeader.dataDirectory->Size);

		i++;
		_peHeader.dataDirectory = &_peHeader.optionalHeader->DataDirectory[i];
	}

}
void __IMPORT_DIRECTORY()
{
	HMODULE hmod;
	hmod = GetModuleHandle(NULL);
	_peHeader.optionalHeader = (PIMAGE_OPTIONAL_HEADER)OPTHDROFFSET(hmod);
	_peHeader.dataDirectory = _peHeader.optionalHeader->DataDirectory;//Import Address Table
	_peHeader.importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)hmod + _peHeader.dataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);



	while (_peHeader.importDescriptor->FirstThunk)
	{
		_peHeader.originalFirstThunk = (PIMAGE_THUNK_DATA)((BYTE*)hmod + _peHeader.importDescriptor->OriginalFirstThunk);
		_peHeader.firstThunk = (PIMAGE_THUNK_DATA)((BYTE*)hmod + _peHeader.importDescriptor->FirstThunk);
		char* dllName = (char*)((BYTE*)hmod + _peHeader.importDescriptor->Name);
		printf_s("[DLL Name]\t[OrginalFirstThunk]\t[FirstThunk]\t[Characteristics]\t[ForwarderChain]\t[TimeStamp]\n\n");
		printf_s("%s\t 0x%X\t\t 0x%X\t 0x%X\t\t %d\t\t %d\t\n\n", dllName, _peHeader.originalFirstThunk, _peHeader.firstThunk, _peHeader.importDescriptor->Characteristics, _peHeader.importDescriptor->ForwarderChain, _peHeader.importDescriptor->TimeDateStamp);
		printf_s("[Function Name]\t\t[Function Address]\n\n");
		while (_peHeader.originalFirstThunk->u1.Function)
		{
			char* funcName = ((BYTE*)hmod + _peHeader.originalFirstThunk->u1.AddressOfData + 2);
			printf_s("%s:\t\t\t0x%X\t\n", funcName, _peHeader.originalFirstThunk->u1.AddressOfData);

			_peHeader.originalFirstThunk++;

		}
		printf("\n\n");
		_peHeader.importDescriptor++;
	}

}
/*void __EXPORT_DIRECTORY()
{
	HINSTANCE hmod;
	hmod = GetModuleHandle("kernel32.dll");
	_peHeader.optionalHeader = (PIMAGE_OPTIONAL_HEADER)OPTHDROFFSET(hmod);
	_peHeader.dataDirectory = _peHeader.optionalHeader->DataDirectory;
	_peHeader.exportDescriptor = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hmod + _peHeader.dataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);



	for (int i=0; i < _peHeader.exportDescriptor->NumberOfFunctions; i++)
	{
		ULONG *address = (ULONG*)((BYTE*)hmod + _peHeader.exportDescriptor->AddressOfFunctions);
	ULONG* name = (ULONG*)((BYTE*)hmod + _peHeader.exportDescriptor->AddressOfNames);
		printf_s("Address : 0x%X\t Name : %s\n",address,name);
		_peHeader.exportDescriptor++;
	}
}*/
void hexdump()
{
	FILE* fp;
	FILE* text;

	int i, c, offset = 0;
	unsigned char buffer[BUF];
	size_t result;


	LPCSTR file = _fileMetadata.fileName;
	fp = fopen(file, "rb");
	if (fp == NULL)
	{
		printf_s("%d", GetLastError());
	}

	LPCSTR fname = strtok(file, ".");
	fname = strcat(file, ".txt");
	text = fopen(fname, "w+");

	if (text == NULL)
	{
		printf_s("%d", GetLastError());
	}

	while (result = fread(buffer, 1, sizeof(buffer), fp) > 0) {
		fprintf(text, "%04x: ", offset);

		offset += BUF;

		for (i = 0; i < BUF; i++)
		{
			fprintf_s(text, "%02x ", buffer[i]);
		}

		for (i = 0; i < BUF; i++) {
			c = buffer[i];
			fprintf_s(text, "%c", (c >= 33 && c <= 128 ? c : '.'));
		}
		fprintf_s(text, "\n");
	}
	fclose(fp);

	text = fopen(fname, "r");

	while ((result = fread(buffer, 1, sizeof buffer, text)) > 0)
	{
		fwrite(buffer, 1, result, stdout);
	}

	fclose(text);
	printf_s("\n\nHex File : %s\n", fname);
}
void _strings()
{
	FILE* fp;
	LPCSTR file = _fileMetadata.fileName;
	int i, c, offset = 0;
	unsigned char buffer[32];
	size_t result;

	fp = fopen(file, "rb");
	if (fp == NULL)
	{
		printf_s("%d", GetLastError());
	}


	while (result = fread(buffer, 1, sizeof(buffer), fp) > 0) {

		for (i = 0; i < 32; i++) {
			c = buffer[i];
			if (c != '\0' && (c >= 65 && c <= 90) || (c >= 97 && c <= 122))
			{
				printf("%c", c);
			}

		}
		printf("\n");
	}

	fclose(fp);
}
