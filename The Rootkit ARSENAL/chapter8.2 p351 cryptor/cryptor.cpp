#include <windows.h>
#include <winnt.h>
#include <stdio.h>

typedef struct _ADDRESS_INFO
{
	DWORD moduleBase;
	DWORD moduleCodeOffset;
	DWORD fileCodeOffset;
	DWORD fileCodeSize;
} ADDRESS_INFO, * PADDRESS_INFO;

BOOL MyGetHMODULE( char* fileName, HANDLE* hFile, HANDLE* hFileMapping, LPVOID* baseAddress )
{
	printf( "[ * ]fileName= %s\n", fileName );
	(*hFile) = CreateFileA( fileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );
	if( hFile == INVALID_HANDLE_VALUE )
	{
		printf( "[ * ]CreateFileA() failed.\n" );
		return( FALSE );
	}
	printf( "[ * ]CreateFileA() success!\n" );

	(*hFileMapping) = CreateFileMapping( *hFile, NULL, PAGE_READONLY, 0, 0, NULL );
	if( (*hFileMapping) == NULL )
	{
		CloseHandle( hFile );
		printf( "[ * ]CreateFileMapping() Failed.\n" );
		return( FALSE );
	}
	printf( "[ * ]CreateFileMapping() Success!.\n" );

	(*baseAddress) = MapViewOfFile( *hFileMapping, FILE_MAP_READ, 0, 0, 0 );
	if( (*baseAddress ) == NULL )
	{
		CloseHandle( *hFileMapping );
		CloseHandle( *hFile );
		printf( "[ * ]MapViewOfFile() Failed.\n" );
		return( FALSE );
	}

	return( TRUE );
}

void TraverseSectionHeaders( PIMAGE_SECTION_HEADER section, DWORD nSections, PADDRESS_INFO addrInfo )
{
	DWORD i;
	printf( "================== Dump Section ==================\n" );
	for( i = 0; i < nSections; i ++ )
	{
		printf( "(*section).Name=		%s\n", (*section).Name );
		printf( "(*section).PointerToRawData=	%X\n", (*section).PointerToRawData );
		printf( "(*section).SizeOfRawDat=	%X\n\n", (*section).SizeOfRawData );
		if( strcmp( (*section).Name, ".text" ) == 0 )
		{
			(*addrInfo).fileCodeOffset = (*section).PointerToRawData;
			(*addrInfo).fileCodeSize = (*section).SizeOfRawData;
		}
		section = section + 1;
	}
	return;
}

void GetCodeLoc( LPVOID baseAddress, PADDRESS_INFO addrInfo )
{
	PIMAGE_DOS_HEADER dosHeader;
	PIMAGE_NT_HEADERS peHeader;
	IMAGE_OPTIONAL_HEADER32 optionalHeader;

	dosHeader = (PIMAGE_DOS_HEADER)baseAddress;
	if( (*dosHeader).e_magic != IMAGE_DOS_SIGNATURE )
	{
		printf( "[ * ](*dosHeader).e_magic is not MZ" );
		return;
	}
	printf( "[ * ](*dosHeader).e_magic = %X\n", (*dosHeader).e_magic );

	peHeader = (PIMAGE_NT_HEADERS)( (BYTE*)baseAddress + (*dosHeader).e_lfanew );
	if( (*peHeader).Signature != IMAGE_NT_SIGNATURE )
	{
		printf( "[ * ](*peHeader).Signature is not PE" );
		return;
	}
	printf( "[ * ](*peHeader).Signature = %X\n", (*peHeader).Signature );

	optionalHeader = (*peHeader).OptionalHeader;
	if( (optionalHeader.Magic) != 0x10B )
	{
		printf( "[ * ]optionalHeader.Magic is not 0x10B" );
		return;
	}
	printf( "[ * ]optionalHeader.Magic = %X\n", optionalHeader.Magic );

	(*addrInfo).moduleBase = optionalHeader.ImageBase;	//DLL 0x10000000  exe 0x00400000
	(*addrInfo).moduleCodeOffset = optionalHeader.BaseOfCode;//.code section size of byte

	printf( "(*peHeader).FileHeader.NumberOfSections=%d\n", (*peHeader).FileHeader.NumberOfSections );//number of sections
	TraverseSectionHeaders( IMAGE_FIRST_SECTION( peHeader ), (*peHeader).FileHeader.NumberOfSections, addrInfo );

	return;
}

void closeHandles( HANDLE hFile, HANDLE hFileMapping, LPVOID baseAddress )
{
	printf( "[ * ]closeHandles()\n" );
	UnmapViewOfFile( baseAddress );
	CloseHandle( hFileMapping );
	CloseHandle( hFile );

	return;
}

void cipherBytes( char* fname, PADDRESS_INFO addrInfo )
{
	DWORD fileOffset;
	DWORD nbytes;

	FILE* fptr;
	BYTE* buffer;
	DWORD nItems;
	DWORD i;

	fileOffset = (*addrInfo).fileCodeOffset;
	nbytes = (*addrInfo).fileCodeSize;

	buffer = (BYTE*)malloc( nbytes );
	if( buffer == NULL )
	{
		free( buffer );
		printf( "[ * ]malloc() Failed\n" );
		return;
	}
	fptr = fopen( fname, "r+b" );
	if( fptr == NULL )
	{
		printf( "[ * ]fopen() failed\n" );
		return;
	}
	if( fseek( fptr, fileOffset, SEEK_SET ) != 0 )
	{
		printf( "[ * ]fseek() failed\n" );
		fclose( fptr );
		return;
	}
	nItems = fread( buffer, sizeof( BYTE ), nbytes, fptr );
	if( nItems < nbytes )
	{
		printf( "[ * ]fread() failed\n" );
		fclose( fptr );
		return;
	}
	for( i = 0; i < nbytes; i ++ )
	{
		buffer[ i ] = buffer[ i ] ^ 0x0F;
	}
	if( fseek( fptr, fileOffset, SEEK_SET ) != 0 )
	{
		printf( "[ * ]fseek() failed\n" );
		fclose( fptr );
		return;
	}
	nItems = fwrite( buffer, sizeof( BYTE ), nbytes, fptr );
	if( nItems < nbytes )
	{
		printf( "[ * ]fwrite() failed\n" );
		fclose( fptr );
		return;
	}

	printf( "[ * ]Success! ciphered %d bytes.\n", nbytes );
	fclose( fptr );
	return;
}

void __cdecl main( int argc, char** argv )
{
	char fileName[ 256 ];
	HANDLE hFile;
	HANDLE hFileMapping;
	LPVOID fileBaseAddress;

	ADDRESS_INFO addrInfo;
	BOOL retVal;

	printf( "fileName > " );
	scanf( "%s", fileName );
	retVal = MyGetHMODULE( fileName, &hFile, &hFileMapping, &fileBaseAddress );
	if( retVal == FALSE )
	{
		return;
	}
	addrInfo.moduleBase = (DWORD)NULL;
	addrInfo.moduleCodeOffset = (DWORD)NULL;
	addrInfo.fileCodeOffset = (DWORD)NULL;
	addrInfo.fileCodeSize = (DWORD)NULL;

	GetCodeLoc( fileBaseAddress, &addrInfo );

	printf( "[ * ]addrInfo.moduleBase=	0x%08X\n", addrInfo.moduleBase );
	printf( "[ * ]addrInfo.moduleCodeOffset=0x%08X\n", addrInfo.moduleCodeOffset );
	printf( "[ * ]addrInfo.fileCodeOffset=	0x%08X\n", addrInfo.fileCodeOffset );
	printf( "[ * ]addrInfo.fileCodeSize=	0x%08X\n", addrInfo.fileCodeSize );

	closeHandles( hFile, hFileMapping, fileBaseAddress );
	cipherBytes( fileName, &addrInfo );

	return;
}