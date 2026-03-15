#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

void __cdecl main( int argc, char* argv[] )
{
	HANDLE		procHandle;
	BOOL		virtualProtect;
	HANDLE		threadHandle;
	HMODULE		dllHandle;
	DWORD		procID;
	FARPROC		loadLibraryAddress;
	LPVOID		baseAddress;
	char argumentBuffer[] = "C:\\IAT_HOOK\\objchk\\i386\\IAT_HOOK.dll";
	BOOL isValid;

	printf( "procID > " );
	scanf( "%d", &procID );

	procHandle = OpenProcess( PROCESS_ALL_ACCESS, FALSE, procID );
	if( procHandle == NULL )
	{
		printf( "procHandle() Failed.\n" );
		return;
	}
	printf( "procHandle() OK.\n" );

	dllHandle = GetModuleHandleA( "kernel32" );
	if( dllHandle == NULL )
	{
		printf( "GetModuleHandleA() Failed.\n" );
		return;
	}
	printf( "GetModuleHandleA() OK.\n" );

	loadLibraryAddress = GetProcAddress( dllHandle, "LoadLibraryA" );
	if( loadLibraryAddress == NULL )
	{
		printf( "GetProcAddress() Failed.\n" );
		return;
	}
	printf( "GetProcAddress() OK.\n" );

	baseAddress = VirtualAllocEx( procHandle, NULL, 256, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
	if( baseAddress == NULL )
	{
		printf( "VirtualAllocEx() Failed.\n" );
		return;
	}
	printf( "VirtualAllocEx() OK.\n" );

	isValid = WriteProcessMemory( procHandle, baseAddress, argumentBuffer, sizeof( argumentBuffer ) + 1, NULL );
	if( isValid == 0 )
	{
		printf( "WriteProcessMemory() Failed.\n" );
		return;
	}
	printf( "WriteProcessMemory() OK.\n" );

	threadHandle = CreateRemoteThread( procHandle, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddress, baseAddress, 0, NULL );

	return;
}