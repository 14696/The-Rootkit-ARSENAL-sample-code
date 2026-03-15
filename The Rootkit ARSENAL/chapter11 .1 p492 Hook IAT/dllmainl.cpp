#include <windows.h>
#include <stdio.h>

#include "hookapi.c"

extern "C"
{
	BOOL APIENTRY DLLMain( HMODULE hModule, DWORD u1_reason_for_call, LPVOID lpReserved )
	{
		switch( u1_reason_for_call )
		{
			case DLL_PROCESS_ATTACH:
			{
				HookAPI( "printMsg" );
			}break;

			case DLL_THREAD_ATTACH:
			break;

			case DLL_THREAD_DETACH:
			break;

			case DLL_PROCESS_DETACH:
			break;
		}
		return( TRUE );
	}
}
