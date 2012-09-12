#ifndef TYPES_H
#define TYPES_H

typedef int Bool;

#define FALSE 0
#define TRUE 1

typedef struct{
	int sesnum;
	int seqnum;
	char* rand;
	char* data;
	int bufSize;
	Bool encode;
} querydata;

typedef struct{
	querydata* q;
	querydata* r;
} qr;



#endif
