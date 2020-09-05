#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>

#define assert(x, msg) \
if (!x) \
{ \
	puts(msg); \
	exit(1); \
}

/// <summary>
/// Type for strings hashed in FNV64
/// </summary>
typedef unsigned long long FNV64;

/// <summary>
/// Type for pointers
/// </summary>
typedef unsigned char* ptr_t;

/// <summary>
/// Counts the length of a string until a null terminator is met
/// </summary>
/// <typeparam name="T">String type</typeparam>
/// <param name="str">Pointer to the string</param>
/// <returns>Length of the string</returns>
template <typename T>
constexpr size_t cx_strlen(const T* str)
{
	size_t len = 0;
	while (str[len++]);
	return len - 1;
}

/// <summary>
/// Hashes a string with FNV
/// </summary>
/// <typeparam name="T">String type</typeparam>
/// <param name="str">String to hash</param>
/// <returns>Hashed string</returns>
template <typename T>
constexpr FNV64 cx_fnv(const T* str)
{
	FNV64 result = 0xcbf29ce484222325;

	while (*str)
		result = (result * 0x00000100000001B3) ^ *str++;

	return result;
}

/// <summary>
/// Hashes a string with FNV partially indicated by the len parameter
/// </summary>
/// <typeparam name="T">String type</typeparam>
/// <param name="str">String to hash</param>
/// <param name="len">Length to hash</param>
/// <returns>Hashed string</returns>
template <typename T>
constexpr FNV64 cx_fnv(const T* str, size_t len)
{
	FNV64 result = 0xcbf29ce484222325;

	while (*str && len-- > 0)
		result = (result * 0x00000100000001B3) ^ *str++;

	return result;
}

/// <summary>
/// Wrapper function for ReadProcessMemory
/// </summary>
/// <typeparam name="T">Read buffer type</typeparam>
/// <param name="hnd">Handle to the process</param>
/// <param name="address">Address to read from</param>
/// <returns>The value read from memory</returns>
template <typename T>
T wRPM(HANDLE hnd, ptr_t address)
{
	T buffer = 0;

	if (!ReadProcessMemory(hnd, address, &buffer, sizeof(T), nullptr))
	{
		printf("ReadProcessMemory failed at address 0x%p", address);
		exit(1);
	}

	return buffer;
}

int main(int argc, const char** argv)
{
	const char* szMsg            = nullptr; // Pointer to the message string to display
	const char* szTitle          = nullptr; // Pointer to the title string to display
	size_t      nMsgLen          = 0;       // Length of szMsg
	size_t      nTitleLen        = 0;       // Length of szTitle

	DWORD       pidCSGO          = 0;       // CSGO's process ID
	HANDLE      hCSGO            = nullptr; // Open process handle to CSGO
	ptr_t       pClientDLL       = nullptr; // Pointer address to the Client DLL's base address
	ptr_t       iGameUI          = nullptr; // GameUI011 interface pointer
	ptr_t       pFnMessageBox    = nullptr; // Pointer to the csgo message box function

	// For debugging purposes, automatically override the parsed args
	#ifdef _DEBUG
		static const char* __debug_defargv[] =
		{
			"",
			"this is a message", // Message box message
			"this is a title"  // Message box title
		};

		argc = 2;
		argv = __debug_defargv;
	#endif

	if (argc < 2)
	{
		puts("Invalid number of args!");
		return 1;
	}

	// Set msg and title from args and get its length
	nMsgLen   = cx_strlen(szMsg   = argv[1]);
	nTitleLen = cx_strlen(szTitle = argv[2]);

	// Find CSGO Process
	{
		puts("Creating process snapshot...");
		HANDLE procSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		assert(procSnap, "Failed to create process snapshot!");

		PROCESSENTRY32 pe32 = { sizeof(PROCESSENTRY32) };

		while (Process32Next(procSnap, &pe32))
		{
			if (cx_fnv(pe32.szExeFile, 8) == cx_fnv(L"csgo.exe"))
			{
				puts("Attaching to CSGO...");
				hCSGO = OpenProcess(PROCESS_ALL_ACCESS, false, pidCSGO = pe32.th32ProcessID);
				break;
			}
		}

		CloseHandle(procSnap);
		assert(hCSGO, "Attaching to CSGO Failed!");

		printf("PID: %d\n"
		       "Handle: 0x%p\n",
			   pidCSGO,
			   hCSGO);
	}

	// Obtain client.dll module
	{
		puts("Creating module snapshot...");
		HANDLE modSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pidCSGO);
		assert(modSnap, "Failed to create module snapshot!");

		MODULEENTRY32 me32 = { sizeof(MODULEENTRY32) };

		while (Module32Next(modSnap, &me32))
		{
			if (cx_fnv(me32.szModule, 10) == cx_fnv(L"client.dll"))
			{
				pClientDLL = reinterpret_cast<ptr_t>(me32.modBaseAddr);
				break;
			}
		}

		CloseHandle(modSnap);
		assert(pClientDLL, "Failed to obtain clienr.dll module base address!");
		printf("client.dll Base address: 0x%p", pClientDLL);
	}

	// Find the export section in the header and obtain a pointer to the CreateInterface
	// Note: Parsing the interface reg might be better solution which doesn't require a shellcode
	{
		// 1. Find the NT header by reading e_lfanew in the DOS header
		printf("\nLocating NT header... ");
		ptr_t _pNTHeader = pClientDLL + wRPM<LONG>(hCSGO,                                               // baseAddress + e_lfanew = address of NT header
												   pClientDLL + sizeof(IMAGE_DOS_HEADER) - sizeof(LONG) // baseAddress + DOS Header size - e_lfanew size = Address of e_lfanew
												   );
		printf("0x%p", _pNTHeader);

		// 2. Get the export directory
		printf("\nLocating export directory... ");
		// nt header + nt header size - data directory array size = First element of DataDirectory which is defined as the IMAGE_DIRECTORY_ENTRY_EXPORT = also the address of the DWORD member VirtualAddress in the IMAGE_DATA_DIRECTORY struct
		ptr_t pExport      = pClientDLL + wRPM<DWORD>(hCSGO, (_pNTHeader + sizeof(IMAGE_NT_HEADERS32)) - (sizeof(IMAGE_OPTIONAL_HEADER32::DataDirectory)));
		DWORD nExportCount = wRPM<DWORD>(hCSGO, (pExport + sizeof(IMAGE_EXPORT_DIRECTORY)) - (sizeof(DWORD) * 4));
		printf("0x%p\nExport count: %d", pExport, nExportCount);

		// 3.a Parse the export directory: Function exports
		printf("\nLocating function export address... ");
		ptr_t pExportFunctions = pClientDLL + wRPM<DWORD>(hCSGO, (pExport + sizeof(IMAGE_EXPORT_DIRECTORY)) - (sizeof(DWORD) * 3)); // export address + size of image export - 3rd dword member from the last = function address RVA
		printf("0x%p", pExportFunctions);

		// 3.b Parse the export directory: Name exports
		printf("\nLocating names export address... ");
		ptr_t pExportNames = pClientDLL + wRPM<DWORD>(hCSGO, (pExport + sizeof(IMAGE_EXPORT_DIRECTORY)) - (sizeof(DWORD) * 2)); // export address + size of image export - 2nd dword member from the last = name address RVA
		printf("0x%p", pExportNames);

		// 3.b Parse the export directory: Name exports
		printf("\nLocating ordinals export address... ");
		ptr_t pExportOrdinals = pClientDLL + wRPM<DWORD>(hCSGO, (pExport + sizeof(IMAGE_EXPORT_DIRECTORY)) - (sizeof(DWORD) * 1)); // export address + size of image export - 1st dword member from the last = ordinal address RVA
		printf("0x%p", pExportOrdinals);

		// 4. Obtain the CreateInterface function export
		ptr_t pFnCreateInterface = nullptr;
		for (DWORD idx = 0; idx < nExportCount; idx++)
		{
			char szFnName[sizeof("CreateInterface") + 1] = { '\0' };
			DWORD rva = wRPM<DWORD>(hCSGO, pExportNames + sizeof(DWORD) * idx);

			if (!ReadProcessMemory(hCSGO, pClientDLL + rva, szFnName, sizeof(szFnName) - 1, nullptr)) // -1 makes sure to leave space for a null terminator
			{
				printf("ReadProcessMemory on export failed at RVA: %x", rva);
				exit(1);
			}

			printf("\n\texport: %s", szFnName);

			if (cx_fnv(szFnName, 15) == cx_fnv("CreateInterface"))
			{
				printf("... Found!\nObtaining CreateInterface address... ");
				pFnCreateInterface = pClientDLL + wRPM<DWORD>(hCSGO, pExportFunctions + sizeof(DWORD) *      // Function RVA
												  wRPM<SHORT>(hCSGO, pExportOrdinals  + sizeof(SHORT) * idx) // Function ordinal
				);
				printf("0x%p", pFnCreateInterface);
				break;
			}
		}

		assert(pFnCreateInterface, "Failed to obtain CreateInterface export");

		// Call CreateInterface and obtain an interface pointer to GameUI011
		// Shellcode to call create interface (https://defuse.ca/online-x86-assembler.htm)
		unsigned char scCallCreateInterface[] =
		{
			0x55, 							 // push   ebp
			0x51,                            // push   ecx
			0x52, 							 // push   edx
			0x89, 0xE5, 					 // mov    ebp,esp
			0xB9, 0x00, 0x00, 0x00, 0x00,    // mov    ecx, pCreateInterface
			0xBA, 0x00, 0x00, 0x00, 0x00, 	 // mov    edx, _pGameUIArg
			0x6A, 0x00, 					 // push   0
			0x52,                       	 // push   edx
			0xFF, 0xD1, 					 // call   ecx
			0x83, 0xC4, 0x08, 				 // add    esp,0x8
			0xA3, 0x00, 0x00, 0x00, 0x00, 	 // mov    ds:_pRetCreateInterface,eax
			0x5A, 							 // pop    edx
			0x59,                            // pop    ecx
			0x5D, 							 // pop    ebp
			0xC3, 							 // ret
			0x47, 0x61, 0x6D, 0x65, 0x55, 0x49, 0x30, 0x31, 0x31, 0x00, // "GameUI011\0"
			0x00, 0x00, 0x00, 0x00                                      // Return value
		};

		// Allocate the shellcode
		printf("\nAllocating memory for CreateInterface shellcode... ");
		LPVOID pShellCodeCreateInterface = VirtualAllocEx(hCSGO, nullptr, sizeof(scCallCreateInterface), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		assert(pShellCodeCreateInterface, "Failed to allocate memory for shellcode");

		// Setup shellcode
		*reinterpret_cast<ptr_t*>(scCallCreateInterface + 0x06) = pFnCreateInterface; // Setup pointer to function call
		*reinterpret_cast<ptr_t*>(scCallCreateInterface + 0x0B) = reinterpret_cast<ptr_t>(pShellCodeCreateInterface) + sizeof(scCallCreateInterface) - sizeof("GameUI011") - sizeof(ptr_t); // Setup arg
		*reinterpret_cast<ptr_t*>(scCallCreateInterface + 0x18) = reinterpret_cast<ptr_t>(pShellCodeCreateInterface) + sizeof(scCallCreateInterface) - sizeof(ptr_t); // Setup address to store return value

		// Write shellcode
		printf("Writing... ");
		assert(WriteProcessMemory(hCSGO, pShellCodeCreateInterface, scCallCreateInterface, sizeof(scCallCreateInterface), nullptr), "Failed to write CreateInterface shellcode");
		printf("0x%p", pShellCodeCreateInterface);

		// Run the shellcode
		printf("\nExecuting shellcode... ");
		HANDLE hCRT = CreateRemoteThread(hCSGO, NULL, 0, (LPTHREAD_START_ROUTINE)pShellCodeCreateInterface, nullptr, 0, nullptr);
		assert(hCRT, "CreateRemoteThread failed!");
		printf("0x%p... Waiting... ", hCRT);
		WaitForSingleObject(hCRT, INFINITE);
		CloseHandle(hCRT);
		puts("Done!");

		// Read the return
		printf("Reading GameUI011 interface... ");
		iGameUI = wRPM<ptr_t>(hCSGO, reinterpret_cast<ptr_t>(pShellCodeCreateInterface) + sizeof(scCallCreateInterface) - sizeof(ptr_t));
		printf("0x%p", iGameUI);

		// Clean up
		assert(VirtualFreeEx(hCSGO, pShellCodeCreateInterface, 0, MEM_RELEASE), "Failed to de-allocate CreateInterface shellcode");
	}

	// Obtain [virtual void ShowMessageDialog(char const* message, char const* title) = 0;] from the IGameUI interface vtable
	{
		// Obtain GameUI011's vtable pointer
		printf("\nReading GameUI011 vtable pointer... ");
		void** pIGUI_vtable = wRPM<void**>(hCSGO, iGameUI); // Type not really necessary but just for readability?
		printf("0x%p", pIGUI_vtable);

		// Obtain the ShowMessageDialog function pointer located at index 20
		printf("\nObtaining ShowMessageDialog pointer... ");
		pFnMessageBox = wRPM<ptr_t>(hCSGO, reinterpret_cast<ptr_t>(pIGUI_vtable) + (sizeof(ptr_t) * 20) );
		printf("0x%p", pFnMessageBox);
		
		// Shellcode to call ShowMessageDialog
		unsigned char scCallMessageBox[] =
		{
			0x55, 							 // push   ebp
			0x50,                            // push   eax
			0x53,                            // push   ebx
			0x51,                            // push   ecx
			0x52, 							 // push   edx
			0x89, 0xE5, 					 // mov    ebp,esp
			0xB8, 0x00, 0x00, 0x00, 0x00,    // mov    eax, pFnMessageBox
			0xB9, 0x00, 0x00, 0x00, 0x00,    // mov    ecx, iGameUI
			0xBB, 0x00, 0x00, 0x00, 0x00,    // mov    ebx, Title
			0xBA, 0x00, 0x00, 0x00, 0x00, 	 // mov    edx, Message
			0x6A, 0x00, 					 // push   0
			0x6A, 0x00, 					 // push   0
			0x6A, 0x00, 					 // push   0
			0x6A, 0x00, 					 // push   0
			0x6A, 0x00, 					 // push   0
			0x6A, 0x00, 					 // push   0
			0x6A, 0x01, 					 // push   1
			0x52,                       	 // push   edx
			0x53,                            // push   ebx
			0xFF, 0xD0, 					 // call   eax
			0x5A, 							 // pop    edx
			0x59,                            // pop    ecx
			0x5B,                            // pop    ebx
			0x58,                            // pop    eax
			0x5D, 							 // pop    ebp
			0xC3, 							 // ret
		};

		// Allocate for the shellcode
		printf("\nAllocating memory for MessageBox shellcode... ");
		LPVOID pShellCodeMessageBox = VirtualAllocEx(hCSGO, nullptr, sizeof(scCallMessageBox) + nMsgLen + nTitleLen + 2, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		assert(pShellCodeMessageBox, "Failed to allocate memory for shellcode");

		// Setup the shellcode
		*reinterpret_cast<ptr_t*>(scCallMessageBox + 0x08) = pFnMessageBox;
		*reinterpret_cast<ptr_t*>(scCallMessageBox + 0x0D) = iGameUI;
		*reinterpret_cast<ptr_t*>(scCallMessageBox + 0x12) = reinterpret_cast<ptr_t>(pShellCodeMessageBox) + sizeof(scCallMessageBox);
		*reinterpret_cast<ptr_t*>(scCallMessageBox + 0x17) = reinterpret_cast<ptr_t>(pShellCodeMessageBox) + sizeof(scCallMessageBox) + nTitleLen + 1;

		// Write shellcode
		printf("Writing... ");
		assert(WriteProcessMemory(hCSGO, pShellCodeMessageBox, scCallMessageBox, sizeof(scCallMessageBox), nullptr), "Failed to write MessageBox shellcode");
		printf("0x%p", pShellCodeMessageBox);

		// Write the title
		printf("\nWriting title w/ length of %d... ", nTitleLen);
		assert(WriteProcessMemory(hCSGO, reinterpret_cast<ptr_t>(pShellCodeMessageBox) + sizeof(scCallMessageBox), szTitle, nTitleLen, nullptr), "Failed to write MessageBox Title");
		puts("Done!");

		// Write the message
		printf("Writing message w/ length of %d... ", nMsgLen);
		assert(WriteProcessMemory(hCSGO, reinterpret_cast<ptr_t>(pShellCodeMessageBox) + sizeof(scCallMessageBox) + nTitleLen + 1, szMsg, nMsgLen, nullptr), "Failed to write MessageBox Title");
		puts("Done!");

		// Run the shellcode
		printf("Executing shellcode... ");
		HANDLE hCRT = CreateRemoteThread(hCSGO, NULL, 0, (LPTHREAD_START_ROUTINE)pShellCodeMessageBox, nullptr, 0, nullptr);
		assert(hCRT, "CreateRemoteThread failed!");
		printf("0x%p... Waiting... ", hCRT);
		WaitForSingleObject(hCRT, INFINITE);
		CloseHandle(hCRT);
		puts("Done!");

		// Clean up
		assert(VirtualFreeEx(hCSGO, pShellCodeMessageBox, 0, MEM_RELEASE), "Failed to de-allocate MessageBox shellcode");
	}

	return 0;
}