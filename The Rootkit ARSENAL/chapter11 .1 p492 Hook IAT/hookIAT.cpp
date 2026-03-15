void __cdecl MyGetCurrentProcessId( char* str )
{
	printf( "%s", str );
}

void processImportDescriptor( IMAGE_IMPORT_DESCRIPTOR importDescriptor, PIMAGE_NT_HEADERS peHeader, DWORD baseAddress, char* apiName )
{
	PIMAGE_THUNK_DATA thunkILT;
	PIMAGE_THUNK_DATA thunkIAT;
	PIMAGE_IMPORT_BY_NAME nameData;
	int nFunctions;
	int nOrdinalFunctions;
	void (__cdecl* procPtr)( char* str );

	thunkILT = (PIMAGE_THUNK_DATA)( importDescriptor.OriginalFirstThunk );
	thunkIAT = (PIMAGE_THUNK_DATA)( importDescriptor.FirstThunk );
	DWORD oldProtect;

	if( thunkILT == NULL )
	{
		printf( "[DEBUG]empty ILT\n" );
		return;
	}
	if( thunkIAT == NULL )
	{
		printf( "[DEBUG]empty IAT\n" );
		return;
	}

	thunkILT = (PIMAGE_THUNK_DATA)( (DWORD)thunkILT + baseAddress );
	if( thunkILT == NULL )
	{
		printf( "[DEBUG]empty ILT\n" );
		return;
	}
	thunkIAT = (PIMAGE_THUNK_DATA)( (DWORD)thunkIAT + baseAddress );
	if( thunkIAT == NULL )
	{
		printf( "[DEBUG]empty IAT\n" );
		return;
	}

	nFunctions = 0;
	nOrdinalFunctions = 0;
	while( (*thunkILT).u1.AddressOfData != 0 )
	{
		if( !( (*thunkILT).u1.Ordinal & IMAGE_ORDINAL_FLAG ) )
		{
			printf( "====================== dump ======================\n" );
			nameData = (PIMAGE_IMPORT_BY_NAME)( (*thunkILT).u1.AddressOfData );
			nameData = (PIMAGE_IMPORT_BY_NAME)( (DWORD)nameData + baseAddress );
			printf( "\t%s", (*nameData).Name );
			printf( "\taddress: %08X", thunkIAT->u1.Function );
			printf( "\n" );

			if( strcmp( apiName, (char*)(*nameData).Name ) == 0 )
			{
				printf( "[DEBUG]found a match for%s\n", apiName );
				/*
				procPtr = MyGetCurrentProcessId;
				thunkIAT->u1.Function = (DWORD)procPtr;
				*/
				procPtr = MyGetCurrentProcessId;
				VirtualProtect( &(thunkIAT->u1.Function ), sizeof( DWORD ), PAGE_READWRITE, &oldProtect );
				thunkIAT->u1.Function = (DWORD)procPtr;
				VirtualProtect( &(thunkIAT->u1.Function ), sizeof( DWORD ), oldProtect, &oldProtect );
			}
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

BOOL walkImportLists( DWORD baseAddress, char* apiName )
{
	PIMAGE_DOS_HEADER dosHeader;
	PIMAGE_NT_HEADERS peHeader;

	IMAGE_OPTIONAL_HEADER32 optionalHeader;
	IMAGE_DATA_DIRECTORY importDirectory;
	DWORD descriptorStartRVA;
	PIMAGE_IMPORT_DESCRIPTOR importDescriptor;
	int index;

	printf( "checking IMAGE_DOS_HEADER.e_magic\n" );
	dosHeader = (PIMAGE_DOS_HEADER)baseAddress;
	if( ( (*dosHeader).e_magic ) != IMAGE_DOS_SIGNATURE )
	{
		printf( "[*]IMAGE_DOS_HEADER.e_magic not a match\n" );
		return( FALSE );
	}
	printf( "[*]IMAGE_DOS_HEADER.e_magic = %X\n", (*dosHeader).e_magic );

	printf( "checking IMAGE_NT_HEADERS.Signature\n" );
	peHeader = (PIMAGE_NT_HEADERS)( (DWORD)baseAddress + (*dosHeader).e_lfanew );
	if( ( (*peHeader).Signature ) != IMAGE_NT_SIGNATURE )
	{
		printf( "[*]IMAGE_NT_HEADERS.Signature not a match\n" );
		return( FALSE );
	}
	printf( "[*]IMAGE_NT_HEADERS.Signature = %X\n", (*peHeader).Signature );

	printf( "[*]checking IMAGE_NT_HEADERS.OptionalHeader.Magic\n" );
	optionalHeader = (*peHeader).OptionalHeader;
	if( ( optionalHeader.Magic ) != 0x10B )
	{
		printf( "IMAGE_NT_HEADERS.OptionalHeader.Magic not a match\n" );
		return( FALSE );
	}
	printf( "IMAGE_NT_HEADERS.OptionalHeader.Magic = %X", optionalHeader.Magic );

	importDirectory = (optionalHeader).DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ];
	descriptorStartRVA = importDirectory.VirtualAddress;
	importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)( descriptorStartRVA + (DWORD)baseAddress );

	index = 0;
	while( importDescriptor[ index ].Characteristics != 0 )
	{
		char* dllName;
		dllName = (char*)( (importDescriptor[ index ] ).Name + (DWORD)baseAddress );
		if( dllName == NULL )
		{
			printf( "[*]Imported DLL[%d]\tNULL Name\n", index );
		}
		else
		{
			printf( "[*]Imported DLL[%d]\t%s\n", index, dllName );
		}
		printf( " ========================================================== \n" );
		processImportDescriptor( importDescriptor[ index ], peHeader, baseAddress, apiName );
		index ++;
	}
	printf( "%d DLLs Imported\n", index );
	return( TRUE );
}

BOOL __cdecl HookAPI( char* apiName )
{
	DWORD baseAddress;

	baseAddress = (DWORD)GetModuleHandle( NULL );	//return HMODULE(void*). cast DWORD
	return( walkImportLists( baseAddress, apiName ) );
}
