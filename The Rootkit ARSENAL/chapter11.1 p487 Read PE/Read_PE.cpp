#include <stdio.h>
#include <windows.h>
#include <winnt.h>

BOOL MYgetMODULE( char* fileName, HANDLE* hFile, HANDLE* hFileMapping, LPVOID* baseAddress )
{
	printf( "[DEBUG]fileName = %s\n", fileName );
	(*hFile) = CreateFileA( fileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );
	if( hFile == INVALID_HANDLE_VALUE )
	{
		printf( "[DEBUG]CreateFileA() Failed.\n" );
		return( FALSE );
	}
	printf( "[DEBUG]CreateFileA() OK.\n" );

	(*hFileMapping) = CreateFileMapping( *hFile, NULL, PAGE_READONLY, 0, 0, NULL );
	if( (*hFileMapping) == NULL )
	{
		CloseHandle( hFile );
		printf( "[DEBUG]CreateFileMapping() Failed.\n" );
		return( FALSE );
	}
	printf( "[DEBUG]CreateFileMapping() OK.\n" );

	(*baseAddress) = MapViewOfFile( *hFileMapping, FILE_MAP_READ, 0, 0, 0 );
	if( (*baseAddress) == NULL )
	{
		CloseHandle( *hFileMapping );
		CloseHandle( *hFile );
		printf( "[DEBUG]MapViewOfFile() Failed.\n" );
		return( FALSE );
	}
	return( TRUE );
}

PIMAGE_SECTION_HEADER MYgetCurrentSectionHeader( DWORD rva, PIMAGE_NT_HEADERS peHeader )
{
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION( peHeader );
	unsigned nSections;
	unsigned index;

	nSections = ( (*peHeader).FileHeader ).NumberOfSections;
	for( index = 0; index < nSections; index ++, section ++ )
	{
		if( (rva >= (*section).VirtualAddress) && ( rva < ( (*section).VirtualAddress + ( (*section).Misc ).VirtualSize ) ) )
		{
			return section;
		}
	}
	return( NULL );
}

LPVOID MYrvaToPtr( DWORD rva, PIMAGE_NT_HEADERS peHeader, DWORD baseAddress )
{
	PIMAGE_SECTION_HEADER sectionHeader;
	INT diffence;
	sectionHeader = MYgetCurrentSectionHeader( rva, peHeader );
	if( sectionHeader == NULL )
	{
		return( NULL );
	}
	diffence = (INT)( (*sectionHeader).VirtualAddress - (*sectionHeader).PointerToRawData );
	return ((PVOID)( ( baseAddress + rva ) - diffence ));
}

void MYprocessImportDescriptor( IMAGE_IMPORT_DESCRIPTOR importDescriptor, PIMAGE_NT_HEADERS peHeader, LPVOID baseAddress )
{
	PIMAGE_THUNK_DATA thunkILT;
	PIMAGE_THUNK_DATA thunkIAT;
	PIMAGE_IMPORT_BY_NAME nameData;
	int nFunctions;
	int nOrdinalFunctions;

	thunkILT = (PIMAGE_THUNK_DATA)( importDescriptor.OriginalFirstThunk );
	thunkIAT = (PIMAGE_THUNK_DATA)( importDescriptor.FirstThunk );

	if( thunkILT == NULL )
	{
		return;
	}
	if( thunkIAT == NULL )
	{
		return;
	}

	thunkILT = (PIMAGE_THUNK_DATA)MYrvaToPtr( (DWORD)thunkILT, peHeader, (DWORD)baseAddress );
	if( thunkILT == NULL )
	{
		return;
	}
	thunkIAT = (PIMAGE_THUNK_DATA)MYrvaToPtr( (DWORD)thunkIAT, peHeader, (DWORD)baseAddress );
	if( thunkIAT == NULL )
	{
		return;
	}

	nFunctions = 0;
	nOrdinalFunctions = 0;
	while( (*thunkILT).u1.AddressOfData != 0 )
	{
		if( !( (*thunkILT).u1.Ordinal & IMAGE_ORDINAL_FLAG ))
		{
			printf( "[(thunkILT)IMAGE_THUNK_DATA.ul.AddressOfData]" );
			nameData = (PIMAGE_IMPORT_BY_NAME)((*thunkILT).u1.AddressOfData );
			nameData = (PIMAGE_IMPORT_BY_NAME)MYrvaToPtr( (DWORD)nameData, peHeader, (DWORD)baseAddress );
			printf( "%s", (*nameData).Name );
			printf( "address: %08X", thunkIAT->u1.Function );
			printf( "\n" );
		}
		else
		{
			nOrdinalFunctions ++;
		}
		thunkILT ++;
		thunkIAT ++;
		nFunctions ++;
	}
	printf( "\t%d functions imported (%d ordinal)\n", nFunctions, nOrdinalFunctions );

	return;
}

void MYdumpImports( LPVOID baseAddress )
{
	PIMAGE_DOS_HEADER dosHeader;
	PIMAGE_NT_HEADERS peHeader;

	IMAGE_OPTIONAL_HEADER32 optionalHeader;
	IMAGE_DATA_DIRECTORY importDirectory;
	DWORD descriptorStartRVA;
	PIMAGE_IMPORT_DESCRIPTOR importDescriptor;

	int index;

	printf( "[DEBUG]checking IMAGE_DOS_HEADER.e_magic\n" );
	dosHeader = (PIMAGE_DOS_HEADER)baseAddress;
	if( ( (*dosHeader).e_magic ) != IMAGE_DOS_SIGNATURE )
	{
		printf( "[DEBUG]IMAGE_DOS_HEADER.e_magic != 0x5A4D\n" );
		return;
	}
	printf( "IMAGE_DOS_HEADER.e_magic = %X\n", (*dosHeader).e_magic );

	printf( "[DEBUG]checking IMAGE_NT_HEADERS.Signature\n" );
	peHeader = (PIMAGE_NT_HEADERS)( (DWORD)baseAddress + (*dosHeader).e_lfanew );
	if( ( (*peHeader).Signature ) != IMAGE_NT_SIGNATURE )
	{
		printf( "[DEBUG]IMAGE_NT_HEADERS.Signature != 0x4550\n" );
		return;
	}
	printf( "IMAGE_NT_HEADERS.Signature = %X\n", (*peHeader).Signature );

	printf( "[DEBUG]checking IMAGE_NT_HEADERS.OptionalHeader\n" );
	optionalHeader = (*peHeader).OptionalHeader;
	if( ( optionalHeader.Magic ) != 0x10B )
	{
		printf( "[DEBUG]IMAGE_NT_HEADERS != 0x10B\n" );
		return;
	}
	printf( "IMAGE_NT_HEADERS.OptionalHeader = %X\n", optionalHeader.Magic );

	importDirectory = (optionalHeader).DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ];
	descriptorStartRVA = importDirectory.VirtualAddress;

	importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)MYrvaToPtr( descriptorStartRVA, peHeader, (DWORD)baseAddress );
	if( importDescriptor == NULL )
	{
		return;
	}
	index = 0;
	while( importDescriptor[ index ].Characteristics != 0 )
	{
		char* dllName;
		dllName = (char*)MYrvaToPtr( ( importDescriptor[ index ] ).Name, peHeader, (DWORD)baseAddress );
		if( dllName == NULL )
		{
			printf( "\n[DEBUG]imported dll[ %d ]\tdllName = NULL\n", index );
		}
		else
		{
			printf( "\n[DEBUG]imported dll[ %d ]\t%s\n", index, dllName );
		}
		printf( "=========================================================================================\n" );
		MYprocessImportDescriptor( importDescriptor[ index ], peHeader, baseAddress );
		index ++;
	}
	printf( "[DEBUG]%d DLLs Imported\n", index );
}

void MYcloseHandles( HANDLE hFile, HANDLE hFileMapping, LPVOID baseAddress )
{
	printf( "[DEBUG]Close\n" );
	UnmapViewOfFile( baseAddress );
	CloseHandle( hFileMapping );
	CloseHandle( hFile );

	return;
}

void __cdecl main( int argc, char* argv[] )
{
	char fileName[ 100 ];
	HANDLE hFile;
	HANDLE hFileMapping;
	LPVOID fileBaseAddress;
	BOOL retVal;

	printf( "fileName > " );
	scanf( "%s", fileName );
	retVal = MYgetMODULE( fileName, &hFile, &hFileMapping, &fileBaseAddress );
	if( retVal == FALSE )
	{
		return;
	}
	MYdumpImports( fileBaseAddress );
	MYcloseHandles( hFile, hFileMapping, fileBaseAddress );

	return;
}
