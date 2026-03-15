#include <windows.h>
#include <stdio.h>

/*
#pragma section( ".code", execute,read,write )
#pragma comment( linker, "/MERGE:.text=.code" )
#pragma comment( linker, "/MERGE:.data=.code" )
#pragma comment( linker, "/SECTION:.code,ERW" )
*/
#pragma comment( linker, "/SECTION:.text,ERW" )
#pragma comment( linker, "/MERGE:.data=.text" )

//#pragma code_seg( ".code" )
#pragma code_seg( ".text" )
unsigned char var[] = { 0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF };

void __cdecl main()
{
	//printf( "main()\n" );
	return;
}

#pragma section( ".stub", execute,read )
#pragma comment( linker, "/entry:\"StubEntry\"" )

#pragma code_seg( ".stub" )

#define CODE_BASE_ADDRESS	0x00401000
#define CODE_SIZE		0x00000200
#define KEY			0x0F

void decryptCodeSection()
{
	unsigned char* ptr;
	long int i;
	long int nbytes;
	ptr = (unsigned char*)CODE_BASE_ADDRESS;
	nbytes = CODE_SIZE;
	for( i = 0; i < nbytes; i ++ )
	{
		ptr[ i ] = ptr[ i ] ^ KEY;
	}
	return;
}

void StubEntry()
{
	decryptCodeSection();
	//printf( "Stub()\n" );
	main();

	return;
}