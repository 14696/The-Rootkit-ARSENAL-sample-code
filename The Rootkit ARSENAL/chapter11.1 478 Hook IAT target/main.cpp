#include <windows.h>
#include <stdio.h>

__declspec( dllimport ) void __cdecl printMsg( char* str );

int __cdecl main( int argc, char* argv[] )
{
	char x[ 1024 ];
	scanf( "%s", x );

	printMsg( x );

	return 0;
}
