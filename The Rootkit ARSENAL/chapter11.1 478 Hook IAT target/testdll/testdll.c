#include <windows.h>
#include <stdio.h>

BOOL __stdcall DLLMain( HINSTANCE hinsDLL, DWORD fdwReason, LPVOID lpReserved )
{
	switch( fdwReason )
	{
		case DLL_PROCESS_ATTACH:
		break;

		case DLL_THREAD_ATTACH:
		break;

		case DLL_THREAD_DETACH:
		break;

		case DLL_PROCESS_DETACH:
		break;
	}
	return( TRUE );
}

__declspec( dllexport ) void __cdecl printMsg( char* str )
{
	printf( "%s", str );
}