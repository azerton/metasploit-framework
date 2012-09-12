#include "ReflectiveLoader.h"
#include <stdio.h>

//===============================================================================================//

// This is our position independent reflective Dll loader/injector

/*-----------------------------------------------------------------------------
IMAGE_FIRST_SECTION32 - Redefined here to remove dependency on NT SDK
-----------------------------------------------------------------------------*/
#define IMAGE_FIRST_SECTION32( ntheader ) ((PIMAGE_SECTION_HEADER)			\
	((UINT_PTR)ntheader +													\
	FIELD_OFFSET( IMAGE_NT_HEADERS32, OptionalHeader ) +					\
	((PIMAGE_NT_HEADERS32)(ntheader))->FileHeader.SizeOfOptionalHeader		\
	))


/*-----------------------------------------------------------------------------
OffsetToRva - Convert a file offset to a relative virtual address
@return -1 if invalid offset is given
-----------------------------------------------------------------------------*/
DWORD FORCEINLINE OffsetToRva(PVOID pModuleBase, DWORD dwFileOffset)
{
	PIMAGE_DOS_HEADER		pDOSHeader			= NULL;
	PIMAGE_NT_HEADERS		pNTHeader			= NULL;		
	PIMAGE_SECTION_HEADER	pSectionHeader		= NULL;
	DWORD					dwSectionNum		= 0;
			
	pDOSHeader = (PIMAGE_DOS_HEADER)pModuleBase;  
	if (pDOSHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return -1;
	pNTHeader = (PIMAGE_NT_HEADERS)((LONG)pDOSHeader + pDOSHeader->e_lfanew);
	if (pNTHeader->Signature != LOWORD(IMAGE_NT_SIGNATURE))
		return -1;		
	pSectionHeader = IMAGE_FIRST_SECTION32(pNTHeader);
	dwSectionNum = pNTHeader->FileHeader.NumberOfSections;

	for (DWORD i = 0; i < dwSectionNum; ++i)
	{
		// Check if offset is within this section
		if (pSectionHeader->PointerToRawData <= dwFileOffset && pSectionHeader->SizeOfRawData + pSectionHeader->PointerToRawData > dwFileOffset)
		{
			// Calculate offset relative to the start of the section
			dwFileOffset -= pSectionHeader->PointerToRawData;
			// Now add the RVA of the section
			dwFileOffset += pSectionHeader->VirtualAddress;
			// And return
			return dwFileOffset;
		}

		pSectionHeader++;
	}

	// Invalid offset => -1
	return -1;
}

/*-----------------------------------------------------------------------------
RvaToOffset - Convert a relative virtual address to a file offset
-----------------------------------------------------------------------------*/
DWORD FORCEINLINE RvaToOffset(PVOID pModuleBase, DWORD dwRva)
{
	PIMAGE_DOS_HEADER		pDOSHeader			= NULL;
	PIMAGE_NT_HEADERS		pNTHeader			= NULL;		
	PIMAGE_SECTION_HEADER	pSectionHeader		= NULL;
	DWORD					dwSectionNum		= NULL;	
			
	pDOSHeader = (PIMAGE_DOS_HEADER)pModuleBase;  
	if (pDOSHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return -1;
	pNTHeader = (PIMAGE_NT_HEADERS)((LONG)pDOSHeader + pDOSHeader->e_lfanew);
	if (pNTHeader->Signature != LOWORD(IMAGE_NT_SIGNATURE))
		return -1;		
	pSectionHeader = IMAGE_FIRST_SECTION32(pNTHeader);
	dwSectionNum = pNTHeader->FileHeader.NumberOfSections;

	for (DWORD i = 0; i < dwSectionNum; ++i)
	{			
		// Check if rva is within this section
		if (pSectionHeader->VirtualAddress <= dwRva && pSectionHeader->Misc.VirtualSize + pSectionHeader->VirtualAddress > dwRva)
		{				
			// Calculate offset relative to RVA of section
			dwRva -= pSectionHeader->VirtualAddress;
			// Now add the RVA of the section
			dwRva += pSectionHeader->PointerToRawData;
			// And return
			return dwRva;
		}

		pSectionHeader++;
	}

	// Invalid offset => -1
	return -1;
}

extern "C" DLLEXPORT DWORD WINAPI ReflectiveLoader( DWORD dwFileBase )
//extern "C" DLLEXPORT DWORD WINAPI ReflectiveLoader( void )
{
	// the functions we need
	LOADLIBRARYA pLoadLibraryA;
	GETPROCADDRESS pGetProcAddress;
	VIRTUALALLOC pVirtualAlloc;
	BYTE bCounter = 3;
	CHAR ansiname[512];

	// the initial location of this image in memory
	DWORD dwLibraryAddress;

	// the kernels base address and later this images newly loaded base address
	DWORD dwBaseAddress;

	// variables for processing the kernels export table
	DWORD dwAddressArray;
	DWORD dwNameArray;
	DWORD dwExportDir;
	DWORD dwNameOrdinals;
	DWORD dwHashValue;

	// variables for loading this image
	DWORD dwHeaderValue;
	DWORD dwValueA;
	DWORD dwValueB;
	DWORD dwValueC;
	DWORD dwValueD;

	// Relocations
	DWORD dwInstructionVa;	
	DWORD dwDelta;
	DWORD dwPreferredBase;

	// STEP 1: process the kernels exports for the functions our loader needs...
	// get the Process Enviroment Block
	/* kernel32.dll lookup was fout op win vista/7 */
	PLIST_ENTRY modlist;
	PLIST_ENTRY modentry;
	__asm
	{
		push ecx
		xor eax, eax
		xor ecx, ecx
		mov eax, fs:[30h]
		mov ecx, dword ptr[eax+0Ch]
		mov eax, dword ptr[ecx+10h]
		mov dword ptr[modentry], eax
		pop ecx
	}

	for (modlist = modentry->Flink; modlist != modentry; modlist = modlist->Flink)
	{		
		PLDR_MODULE ldrmod = (PLDR_MODULE)modlist;

		if (ldrmod->BaseAddress)
		{
			INT strLen = ldrmod->BaseDllName.Length/2;			
			ansiname[0] = '\0';

			if (strLen > 0)
			{				
				for (INT i = 0; i < strLen; ++i)
					if (*(CHAR*)(ldrmod->BaseDllName.Buffer + i))
						ansiname[i] = *(CHAR*)(ldrmod->BaseDllName.Buffer + i);
				ansiname[strLen] = '\0';
			}
			
			dwHashValue = __hash(ansiname);
			if (dwHashValue == KERNEL32_HASH)
			{
				//printf("Found Module: %s - 0x%08X - Hash: 0x%08X\n", ansiname, ldrmod->BaseAddress, dwHashValue);
				dwBaseAddress = (DWORD)ldrmod->BaseAddress;
			}
		}
	}

	// get the VA of the modules NT Header
	dwExportDir = dwBaseAddress + ((PIMAGE_DOS_HEADER)dwBaseAddress)->e_lfanew;

	// dwNameArray = the address of the modules export directory entry
	dwNameArray = (DWORD)&((PIMAGE_NT_HEADERS32)dwExportDir)->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];

	// get the VA of the export directory
	dwExportDir = ( dwBaseAddress + ((PIMAGE_DATA_DIRECTORY)dwNameArray)->VirtualAddress );

	// get the VA for the array of name pointers
	dwNameArray = ( dwBaseAddress + ((PIMAGE_EXPORT_DIRECTORY )dwExportDir)->AddressOfNames );

	// get the VA for the array of name ordinals
	dwNameOrdinals = ( dwBaseAddress + ((PIMAGE_EXPORT_DIRECTORY )dwExportDir)->AddressOfNameOrdinals );	

	// loop while we still have imports to find
	for (INT i = 0; i < ((PIMAGE_EXPORT_DIRECTORY )dwExportDir)->NumberOfNames; ++i) 
	{				
		// compute the hash values for this function name		
		dwHashValue = __hash( (char *)( dwBaseAddress + DEREF_32( dwNameArray ) )  );		

		// if we have found a function we want we get its virtual address
		if( dwHashValue == LOADLIBRARYA_HASH || dwHashValue == GETPROCADDRESS_HASH || dwHashValue == VIRTUALALLOC_HASH )
		{
			// get the VA for the array of addresses
			dwAddressArray = ( dwBaseAddress + ((PIMAGE_EXPORT_DIRECTORY )dwExportDir)->AddressOfFunctions );

			// use this functions name ordinal as an index into the array of name pointers
			dwAddressArray += ( DEREF_16( dwNameOrdinals ) * sizeof(DWORD) );

			// store this functions VA
			if( dwHashValue == LOADLIBRARYA_HASH )
				pLoadLibraryA = (LOADLIBRARYA)( dwBaseAddress + DEREF_32( dwAddressArray ) );
			else if( dwHashValue == GETPROCADDRESS_HASH )
				pGetProcAddress = (GETPROCADDRESS)( dwBaseAddress + DEREF_32( dwAddressArray ) );
			else if( dwHashValue == VIRTUALALLOC_HASH )
				pVirtualAlloc = (VIRTUALALLOC)( dwBaseAddress + DEREF_32( dwAddressArray ) );

			// decrement our counter
			bCounter--;
		}

		if (bCounter == 0)
			break;

		// get the next exported function name
		dwNameArray += sizeof(DWORD);

		// get the next exported function name ordinal
		dwNameOrdinals += sizeof(WORD);
	}	

	// STEP 2: load our image into a new permanent location in memory...
	// get the VA of the NT Header for the PE to be loaded
	dwLibraryAddress = dwFileBase;
	//dwLibraryAddress = dwBaseAddress;

	dwHeaderValue = dwLibraryAddress + ((PIMAGE_DOS_HEADER)dwLibraryAddress)->e_lfanew;
	dwPreferredBase = ((PIMAGE_NT_HEADERS32)dwHeaderValue)->OptionalHeader.ImageBase;

	// allocate all the memory for the DLL to be loaded into. we can load at any address because we will  
	// relocate the image. Also zeros all memory and marks it as READ, WRITE and EXECUTE to avoid any problems.
	dwBaseAddress = (DWORD)pVirtualAlloc( NULL, ((PIMAGE_NT_HEADERS32)dwHeaderValue)->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE );	
	dwDelta =  dwBaseAddress - dwPreferredBase;

	// we must now copy over the headers
	dwValueA = ((PIMAGE_NT_HEADERS32)dwHeaderValue)->OptionalHeader.SizeOfHeaders;
	dwValueB = dwLibraryAddress;
	dwValueC = dwBaseAddress;
	__memcpy( dwValueC, dwValueB, dwValueA );

	// STEP 3: load in all of our sections...
	// dwValueA = the VA of the first section
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION32((PIMAGE_NT_HEADERS)dwHeaderValue);

	// itterate through all sections, loading them into memory.
	for (INT i = 0; i < ((PIMAGE_NT_HEADERS)dwHeaderValue)->FileHeader.NumberOfSections; ++i)
	{
		// dwValueB is the VA for this section
		dwValueB = ( dwBaseAddress + pSection->VirtualAddress );

		// dwValueC if the VA for this sections data
		dwValueC = ( dwLibraryAddress + pSection->PointerToRawData ); // Copy from a module dumped directly from the disk
		//dwValueC = dwLibraryAddress + pSection->VirtualAddress; // Copy from a module loaded via loadlibrary

		// copy the section over
		dwValueD = pSection->SizeOfRawData;
		__memcpy( dwValueB, dwValueC, dwValueD );

		pSection++;
	}

	// STEP 4: process our images import table...
	// dwValueB = the address of the import directory
	dwValueB = (DWORD)&((PIMAGE_NT_HEADERS32)dwHeaderValue)->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ];

	// we assume their is an import table to process
	// dwValueC is the first entry in the import table
	dwValueC = ( dwBaseAddress + ((PIMAGE_DATA_DIRECTORY)dwValueB)->VirtualAddress );

	// itterate through all imports
	/* import by name lookup was fout (FirstThunk werd gebruikt ipv OriginalFirstThunk) */
	while( ((PIMAGE_IMPORT_DESCRIPTOR)dwValueC)->Name )
	{		
		// use LoadLibraryA to load the imported module into memory
		dwLibraryAddress = (DWORD)pLoadLibraryA( (LPCSTR)( dwBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)dwValueC)->Name ) );		

		// dwValueD = VA of the OriginalFirstThunk
		dwValueD = ( dwBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)dwValueC)->OriginalFirstThunk );

		// dwValueA = VA of the IAT (via first thunk not origionalfirstthunk)
		dwValueA = ( dwBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)dwValueC)->FirstThunk );

		// itterate through all imported functions, importing by ordinal if no name present
		while( DEREF_32(dwValueA) )
		{			
			if( dwValueD && ((PIMAGE_THUNK_DATA)dwValueD)->u1.Ordinal & IMAGE_ORDINAL_FLAG32 )
			{
				// get the VA of the modules NT Header
				dwExportDir = dwLibraryAddress + ((PIMAGE_DOS_HEADER)dwLibraryAddress)->e_lfanew;

				// dwNameArray = the address of the modules export directory entry
				dwNameArray = (DWORD)&((PIMAGE_NT_HEADERS32)dwExportDir)->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];

				// get the VA of the export directory
				dwExportDir = ( dwLibraryAddress + ((PIMAGE_DATA_DIRECTORY)dwNameArray)->VirtualAddress );

				// get the VA for the array of addresses
				dwAddressArray = ( dwLibraryAddress + ((PIMAGE_EXPORT_DIRECTORY )dwExportDir)->AddressOfFunctions );

				// use the import ordinal (- export ordinal base) as an index into the array of addresses
				dwAddressArray += ( ( IMAGE_ORDINAL32( ((PIMAGE_THUNK_DATA)dwValueD)->u1.Ordinal ) - ((PIMAGE_EXPORT_DIRECTORY )dwExportDir)->Base ) * sizeof(DWORD) );

				// patch in the address for this imported function
				DEREF_32(dwValueA) = ( dwLibraryAddress + DEREF_32(dwAddressArray) );
			}
			else
			{
				// get the VA of this functions import by name struct
				dwValueB = ( dwBaseAddress + DEREF_32(dwValueD) );

				// use GetProcAddress and patch in the address for this imported function				
				DEREF_32(dwValueA) = (DWORD)pGetProcAddress( (HMODULE)dwLibraryAddress, (LPCSTR)((PIMAGE_IMPORT_BY_NAME)dwValueB)->Name );
			}

			// get the next imported function
			dwValueA += 4;

			if( dwValueD )
				dwValueD += 4;
		}

		// get the next import
		dwValueC += sizeof( IMAGE_IMPORT_DESCRIPTOR );
	}

	// STEP 5: process all of our images relocations...
	// calculate the base address delta and perform relocations (even if we load at desired image base)	
	/* Relocatieproces was volledig fout - relocaties werden toegepast op de relocatietabel ipv op de code */
	dwLibraryAddress = dwBaseAddress - ((PIMAGE_NT_HEADERS32)dwHeaderValue)->OptionalHeader.ImageBase;

	// dwValueB = the address of the relocation directory
	dwValueB = (DWORD)&((PIMAGE_NT_HEADERS32)dwHeaderValue)->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ];

	// check if their are any relocations present
	if( ((PIMAGE_DATA_DIRECTORY)dwValueB)->Size )
	{
		// dwValueC is now the first entry (IMAGE_BASE_RELOCATION)
		dwValueC = ( dwBaseAddress + ((PIMAGE_DATA_DIRECTORY)dwValueB)->VirtualAddress );

		// and we itterate through all entries...
		while( ((PIMAGE_BASE_RELOCATION)dwValueC)->SizeOfBlock )
		{	
			// dwValueA = the VA for this relocation block
			dwValueA = ( dwBaseAddress + ((PIMAGE_BASE_RELOCATION)dwValueC)->VirtualAddress );

			// dwValueB = number of entries in this relocation block
			dwValueB = ( ((PIMAGE_BASE_RELOCATION)dwValueC)->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION) ) / sizeof( WORD );

			// dwValueD is now the first entry in the current relocation block
			dwValueD = dwValueC + sizeof(IMAGE_BASE_RELOCATION);						

			// we itterate through all the entries in the current block...
			while( dwValueB-- )
			{			
				// perform the relocation, skipping IMAGE_REL_BASED_ABSOLUTE as required				
				switch(((*(WORD*)dwValueD) & 0xF000) >> 12)
				{					
					case IMAGE_REL_BASED_HIGHLOW:
						{
							//printf("Found relocation: 0x%08X - dwDelta: 0x%08X\n", (*(WORD*)dwValueD & 0x0FFF) + dwValueA, dwDelta);
							dwInstructionVa	= (*(WORD*)dwValueD & 0x0FFF) + dwValueA;							
							*(DWORD*)(dwInstructionVa) += dwDelta;						
							break;
						}
				}

				// get the next entry in the current relocation block
				dwValueD += sizeof( WORD );
			}

			// get the next entry in the relocation directory
			dwValueC = dwValueC + ((PIMAGE_BASE_RELOCATION)dwValueC)->SizeOfBlock;
		}		
	}

	return (DWORD)dwBaseAddress;

}

//===============================================================================================//

