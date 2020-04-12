#pragma once
#pragma warning(disable:4996)
#pragma comment (lib, "wintrust")


#define SIZE_OF_NT_SIGNATURE sizeof(IMAGE_NT_SIGNATURE)
#define NTSIGNATURE(a) ((LPVOID)((BYTE *)a + ((PIMAGE_DOS_HEADER)a)->e_lfanew))
#define OPTHDROFFSET(a) ((LPVOID)((BYTE *)a + ((PIMAGE_DOS_HEADER)a)->e_lfanew + SIZE_OF_NT_SIGNATURE + sizeof (IMAGE_FILE_HEADER)))
#define PEFHDROFFSET(a) ((LPVOID)((BYTE *)a + ((PIMAGE_DOS_HEADER)a)->e_lfanew + SIZE_OF_NT_SIGNATURE))
#define SECHDROFFSET(a) ((LPVOID)((BYTE *)a + ((PIMAGE_DOS_HEADER)a)->e_lfanew + SIZE_OF_NT_SIGNATURE + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER)))
#define OPTHDROFFSET(a) ((LPVOID)((BYTE *)a + ((PIMAGE_DOS_HEADER)a)->e_lfanew + SIZE_OF_NT_SIGNATURE + sizeof (IMAGE_FILE_HEADER)))
#define NUMOFSECTION(a) ((DWORD)((PIMAGE_FILE_HEADER) PEFHDROFFSET(a))->NumberOfSections);

#define IMAGE_DIRECTORY_ENTRY_EXPORT 0   // Export Directory
#define IMAGE_DIRECTORY_ENTRY_IMPORT 1   // Import Directory

#define RVA2VA(type, base, rva) (type)((ULONG_PTR) base + rva) 
//base =hFile
//_peHeader.optionalHeader->DataDirectory[1].VirtualAddress
//_hfile + _peHeader.optionalHeader->DataDirectory[1].VirtualAddress

#define BUF_SIZE 1024
#define MD5LEN 16
#define SHA1LEN 20
#define BUF 16
#define BUFSIZE 1024


#define HELP "--help" 
#define VERSION "--version" 
#define DOS_HEADER "-dh" 
#define NT_HEADER "-nt" 
#define FILE_HEADER "-fh" 
#define OPTIONAL_HEADER "-oh" 
#define SECTION_HEADER "-sh"
#define DATA_DIRECTORY "-dd" 
#define IMPORT_DIRECTORY "-id"
//#define VIRUSTOTAL "-vt"
#define HEXDUMP "-h"
#define STRINGS "-s" 

//#define VERIFY_SIGNATURE "-vs"
//#define PARAMETERS "-?" //Bu parametre hakkýnda bilgi versin yani Project11.exe -fi -?


/*
-fi --File Information
-sh --Section Header
-ih --Image File Header
-dh --Dos Header
-nt --NT Header
-oh --Optional Header
-dd --Data Directory
-id --Import Directory
-ed --Export Directory
-vc --Virustotal Control
-h --Hex Dump
-s --Strings

-help
-?
-version
*/

struct fileMetadata
{
	DWORD dwFileSize;
	HANDLE hFile;
	HANDLE hFileMapping;
	HANDLE hFileBase;
	DWORD machine;
	const char* fileName;
};

struct peHeader
{
	PIMAGE_DOS_HEADER dosHeader;
	PIMAGE_FILE_HEADER fileHeader;
	PIMAGE_OPTIONAL_HEADER optionalHeader;
	PIMAGE_NT_HEADERS ntHeader;
	PIMAGE_SECTION_HEADER sectionHeader;
	PIMAGE_DATA_DIRECTORY dataDirectory;
	PIMAGE_IMPORT_DESCRIPTOR importDescriptor;
	PIMAGE_EXPORT_DIRECTORY exportDescriptor;
	PIMAGE_THUNK_DATA originalFirstThunk;
	PIMAGE_THUNK_DATA firstThunk;
};

struct peHash
{
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	BYTE rgbFile[BUF_SIZE];
	BYTE rgbHash[SHA1LEN];
	DWORD cbHash;
	DWORD cbRead;
	char rgbDigits[16];
};

struct peHeader _peHeader;
struct peHash _peHash;
struct fileMetadata _fileMetadata;

BYTE typeName[9][30] = { "Name","Virtual Size","Virtual Address","Raw Size","Raw Address","Reloc Address","Linenumbers","Relocation Numbers","Linenumbers Numbers" };
BYTE directory[16][50] = { "Export Directory","Import Directory","Resource Directory","Exception Directory","Certificate Table","Base Relocation Table","Debug Directory","Architecture-Specific Data","Global Pointer Register RVA","Thread Local Storage (TLS) Table","Load Configuration Table","Bound Import Table","Import Address Table","Delay Import Descriptor","The CLR Header","Reserver" };
const static char _md5[] = "MD5";
const static  char _sha1[] = "SHA1";


void __IMAGE_FILE_HEADER(HANDLE _hFileBase);
void __DOS_HEADER(HANDLE _hFileBase);
void __NT_HEADER(HANDLE _hFileBase);
void __FILE_HEADER(HANDLE _hFileBase);
void __OPTIONAL_HEADER(HANDLE _hFileBase);
void __DATA_DIRECTORY(HANDLE _hFileBase);
void __IMPORT_DIRECTORY();
void __EXPORT_DIRECTORY();
void __FILE_METADATA();
void mapping();
void _getHashFile(HANDLE _hFile, const char _hash[], int _len, ALG_ID _alg);
void timeConvert(DWORD _time);
void fileTimeConvert(HANDLE _hFile);
void hexdump();
void _strings();
void enter();
void help();
void version();
void verifySignature();

static unsigned char logo[] = {
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x5f, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x5f, 0x20, 0x20, 0x20, 0x20, 0x5f,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x0d, 0x0a, 0x20, 0x5f, 0x20, 0x5f, 0x5f,
	0x20, 0x28, 0x5f, 0x29, 0x20, 0x5f, 0x5f, 0x5f, 0x7c, 0x20,
	0x7c, 0x20, 0x5f, 0x7c, 0x20, 0x7c, 0x20, 0x5f, 0x5f, 0x5f,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x5f, 0x20, 0x5f,
	0x5f, 0x20, 0x20, 0x20, 0x5f, 0x5f, 0x5f, 0x20, 0x0d, 0x0a,
	0x7c, 0x20, 0x27, 0x5f, 0x20, 0x5c, 0x7c, 0x20, 0x7c, 0x2f,
	0x20, 0x5f, 0x5f, 0x7c, 0x20, 0x7c, 0x2f, 0x20, 0x2f, 0x20,
	0x7c, 0x2f, 0x20, 0x5f, 0x20, 0x5c, 0x5f, 0x5f, 0x5f, 0x5f,
	0x5f, 0x7c, 0x20, 0x27, 0x5f, 0x20, 0x5c, 0x20, 0x2f, 0x20,
	0x5f, 0x20, 0x5c, 0x0d, 0x0a, 0x7c, 0x20, 0x7c, 0x5f, 0x29,
	0x20, 0x7c, 0x20, 0x7c, 0x20, 0x28, 0x5f, 0x5f, 0x7c, 0x20,
	0x20, 0x20, 0x3c, 0x7c, 0x20, 0x7c, 0x20, 0x20, 0x5f, 0x5f,
	0x2f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x7c, 0x20, 0x7c, 0x5f,
	0x29, 0x20, 0x7c, 0x20, 0x20, 0x5f, 0x5f, 0x2f, 0x0d, 0x0a,
	0x7c, 0x20, 0x2e, 0x5f, 0x5f, 0x2f, 0x7c, 0x5f, 0x7c, 0x5c,
	0x5f, 0x5f, 0x5f, 0x7c, 0x5f, 0x7c, 0x5c, 0x5f, 0x5c, 0x5f,
	0x7c, 0x5c, 0x5f, 0x5f, 0x5f, 0x7c, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x7c, 0x20, 0x2e, 0x5f, 0x5f, 0x2f, 0x20, 0x5c, 0x5f,
	0x5f, 0x5f, 0x7c, 0x0d, 0x0a, 0x7c, 0x5f, 0x7c, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x7c, 0x5f, 0x7c, 0x20,
	0x20, 0x20, 0x20, 0x20,0x00
};
