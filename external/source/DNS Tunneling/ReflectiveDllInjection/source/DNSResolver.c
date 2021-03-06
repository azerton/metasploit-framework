//Header Files
#include "types.h"
#include "DNSResolver.h"
#include "queryops.h"

#include "winsock2.h"
#include "windows.h"
#include "stdio.h"
#include "conio.h"

#pragma comment(lib,"ws2_32.lib")   //Winsock Library

//List of DNS Servers registered on the system
char dns_servers[10][100];

querydata* resolveDNS(querydata* qd)
{
	unsigned char buf[65536],*qname,*reader;
	
	char host[512];
	unsigned int i , j , stop;
	
	SOCKET s;
	struct sockaddr_in a;

	struct RES_RECORD answers[20],auth[20],addit[20];  //the replies from the DNS server
	struct sockaddr_in dest;
	
	struct DNS_HEADER *dns = NULL;
	struct QUESTION   *qinfo = NULL;
	
	querydata* qda = malloc(sizeof(querydata));

	s = socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);  //UDP packet for DNS queries

	dest.sin_family=AF_INET;
	dest.sin_port=htons(53);
	
	//dest.sin_addr.s_addr=inet_addr(dns_servers[0]);  //dns servers
	//Hard code DNS server for now
	//dest.sin_addr.s_addr=inet_addr("192.168.1.4");  //dns servers
	dest.sin_addr.s_addr=inet_addr("8.8.8.8");  //dns servers

	//Set the DNS structure to standard queries
	dns = (struct DNS_HEADER *)&buf;
	
	#pragma warning( push )
	#pragma warning( disable : 4244 )
	dns->id = (unsigned short) (htons(GetCurrentProcessId()));
	#pragma warning( pop )

	dns->qr = 0;      //This is a query
	dns->opcode = 0;  //This is a standard query
	dns->aa = 0;      //Not Authoritative
	dns->tc = 0;      //This message is not truncated
	dns->rd = 1;      //Recursion Desired
	dns->ra = 0;      //Recursion not available! hey we dont have it (lol)
	dns->z  = 0;
	dns->ad = 0;
	dns->cd = 0;
	dns->rcode = 0;
	dns->q_count = htons(1);   //we have only 1 question
	dns->ans_count  = 0;
	dns->auth_count = 0;
	dns->add_count  = 0;
	
	//Encode querydata as URL
	strcpy(host, encodeQuery(qd));
	
	//point to the query portion
	qname =(unsigned char*)&buf[sizeof(struct DNS_HEADER)];
    
	ChangetoDnsNameFormat(qname, host);
	qinfo =(struct QUESTION*)&buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)]; //fill it

	qinfo->qtype = htons(5);  //we are requesting the CNAME (canonical name)
	qinfo->qclass = htons(1); //its internet

	//printf("\nSending Packet...");
	if(sendto(s,(char*)buf,sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION),0,(struct sockaddr*)&dest,sizeof(dest))==SOCKET_ERROR)
	{
		printf("%d  error",WSAGetLastError());
	}
	//printf("Sent");
	
	i=sizeof(dest);
	//printf("\nReceiving answer...");
	if(recvfrom (s,(char*)buf,65536,0,(struct sockaddr*)&dest,&i)==SOCKET_ERROR)
	{
		printf("Failed. Error Code : %d\n",WSAGetLastError());
	}
	//printf("Received.");
	
	dns=(struct DNS_HEADER*)buf;
	
	//move ahead of the dns header and the query field
	reader=&buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION)];

    //printf("\nThe response contains : ");
	//printf("\n %d Questions.",ntohs(dns->q_count));
	//printf("\n %d Answers.",ntohs(dns->ans_count));
	//printf("\n %d Authoritative Servers.",ntohs(dns->auth_count));
	//printf("\n %d Additional records.\n\n",ntohs(dns->add_count));
	
	//reading answers
	stop=0;
	
	for(i=0;i<ntohs(dns->ans_count);i++)
	{
		answers[i].name=ReadName(reader,buf,&stop);
		reader = reader + stop;
		
		answers[i].resource = (struct R_DATA*)(reader);
		reader = reader + sizeof(struct R_DATA);
	
		if(ntohs(answers[i].resource->type) == 1) //if its an ipv4 address
		{
			answers[i].rdata = (unsigned char*)malloc(ntohs(answers[i].resource->data_len));
			
			for(j=0 ; j<ntohs(answers[i].resource->data_len) ; j++)
				answers[i].rdata[j]=reader[j];
			
			answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';
			
			reader = reader + ntohs(answers[i].resource->data_len);
		
		}
		else
		{
			answers[i].rdata = ReadName(reader,buf,&stop);
		    reader = reader + stop;
		}
		
		
	}
	
	//read authorities
	for(i=0;i<ntohs(dns->auth_count);i++)
	{
		auth[i].name=ReadName(reader,buf,&stop);
		reader+=stop;
		
		auth[i].resource=(struct R_DATA*)(reader);
		reader+=sizeof(struct R_DATA);
	
		auth[i].rdata=ReadName(reader,buf,&stop);
		reader+=stop;
	}

	//read additional
	for(i=0;i<ntohs(dns->add_count);i++)
	{
		addit[i].name=ReadName(reader,buf,&stop);
		reader+=stop;
		
		addit[i].resource=(struct R_DATA*)(reader);
		reader+=sizeof(struct R_DATA);
	
		if(ntohs(addit[i].resource->type)==1)
		{
			addit[i].rdata = (unsigned char*)malloc(ntohs(addit[i].resource->data_len));
			for(j=0;j<ntohs(addit[i].resource->data_len);j++)
				addit[i].rdata[j]=reader[j];

			addit[i].rdata[ntohs(addit[i].resource->data_len)]='\0';
			reader+=ntohs(addit[i].resource->data_len);
		
		}
		else
		{
			addit[i].rdata=ReadName(reader,buf,&stop);
		    reader+=stop;
		}
	}

	//print answers
	for(i=0;i<ntohs(dns->ans_count);i++)
	{
		//printf("\nAnswer : %d",i+1);
		//printf("Name  :  %s ",answers[i].name);
			
		if(ntohs(answers[i].resource->type)==1)   //IPv4 address
		{
			
			long *p;
			p=(long*)answers[i].rdata;
			a.sin_addr.s_addr=(*p);    //working without ntohl
			printf("has IPv4 address :  %s",inet_ntoa(a.sin_addr));
		}
		if(ntohs(answers[i].resource->type)==5)   //Canonical name for an alias. This is the kind of records we want for the tunnel.
			//printf("Answer from server: %s\n", (char*)answers[i].rdata);
			qda =  decodeResponse((char*)answers[i].rdata); //return the first canonical response
		//printf("\n");
	}

	//print authorities
	for(i=0;i<ntohs(dns->auth_count);i++)
	{
		//printf("\nAuthorities : %d",i+1);
		//printf("Name  :  %s ",auth[i].name);
		if(ntohs(auth[i].resource->type)==2)
			printf("has authoritative nameserver : %s",auth[i].rdata);
		//printf("\n");
	}

	//print additional resource records
	for(i=0;i<ntohs(dns->add_count);i++)
	{
		//printf("\nAdditional : %d",i+1);
		//printf("Name  :  %s ",addit[i].name);
		if(ntohs(addit[i].resource->type)==1)
		{
			long *p;
			p=(long*)addit[i].rdata;
			a.sin_addr.s_addr=(*p);    //working without ntohl
			printf("has IPv4 address :  %s",inet_ntoa(a.sin_addr));
		}
		//printf("\n");
	}
    return qda;
}

unsigned char* ReadName(unsigned char* reader,unsigned char* buffer,int* count)
{
	unsigned char *name;
	unsigned int p=0,jumped=0,offset;
	int i , j;

	*count = 1;
	name   = (unsigned char*)malloc(256);
	
	name[0]='\0';

	//read the names in 3www6google3com format
	while(*reader!=0)
	{
		if(*reader>=192)
		{
			offset = (*reader)*256 + *(reader+1) - 49152; //49152 = 11000000 00000000  ;)
			reader = buffer + offset - 1;
			jumped = 1;  //we have jumped to another location so counting wont go up!
		}
		else 
			name[p++]=*reader;
		
		reader=reader+1;
		
		if(jumped==0) *count = *count + 1; //if we havent jumped to another location then we can count up
	}
	
	name[p]='\0';    //string complete
	if(jumped==1) *count = *count + 1;  //number of steps we actually moved forward in the packet
	
	//now convert 3www6google3com0 to www.google.com
	for(i=0;i<(int)strlen((const char*)name);i++)
	{
		p=name[i];
		for(j=0;j<(int)p;j++)
		{
			name[i]=name[i+1];
			i=i+1;
		}
		name[i]='.';
	}
	name[i-1]='\0';	  //remove the last dot
	return name;		
}


//Retrieve the DNS servers from the registry
void RetrieveDnsServersFromRegistry()
{
	HKEY hkey=0;
	char name[256];
	char *path="SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces";
	char *fullpath[256];
	unsigned long s=sizeof(name);
	int  dns_count=0 , err;
	int i , j;
	HKEY inter;
	unsigned long count;


	//Open the registry folder
	RegOpenKeyEx(HKEY_LOCAL_MACHINE , path , 0 , KEY_READ , &hkey );
		
	
	
	//how many interfaces
	RegQueryInfoKey(hkey, 0 , 0 , 0 , &count , 0 , 0 , 0 , 0 , 0 , 0 , 0 );
	
	for(i=0;(unsigned int)i<count;i++)
	{
		s=256;
		//Get the interface subkey name
		RegEnumKeyEx(hkey , i , (char*)name , &s , 0 , 0 , 0 , 0 );
		
		//Make the full path
		strcpy((char*)fullpath,path);
		strcat((char*)fullpath,"\\");
		strcat((char*)fullpath,name);
				
		//Open the full path name
		RegOpenKeyEx(HKEY_LOCAL_MACHINE , (const char*)fullpath , 0 , KEY_READ , &inter );
				
		//Extract the value in Nameserver field
		s=256;
		err=RegQueryValueEx(inter , "NameServer" , 0 , 0 , (unsigned char*)name ,	&s );
		
		if(err==ERROR_SUCCESS && strlen(name)>0) strcpy(dns_servers[dns_count++],name);
	}

	for(i=0;i<dns_count;i++)
	{
		for(j=0;(unsigned int)j<strlen(dns_servers[i]);j++)
		{
			if(dns_servers[i][j]==',' || dns_servers[i][j]==' ')
			{
				strcpy(dns_servers[dns_count++],dns_servers[i]+j+1);
				dns_servers[i][j]=0;
			}
		}
	}

	printf("\nThe following DNS Servers were found on your system...");
	for(i=0;i<dns_count;i++)
	{
		printf("\n%d)  %s",i+1,dns_servers[i]);
	}
}


//this will convert www.google.com to 3www6google3com ;got it :)
void ChangetoDnsNameFormat(unsigned char* dns,unsigned char* host)
{
	int lock=0 , i;
	
	strcat((char*)host,".");
	
	for(i=0;i<(int)strlen((char*)host);i++)
	{
		if(host[i]=='.')
		{
			*dns++=i-lock;
			for(;lock<i;lock++)
			{
				*dns++=host[lock];
			}
			lock++; //or lock=i+1;
		}
	}
    *dns++='\0';
}



