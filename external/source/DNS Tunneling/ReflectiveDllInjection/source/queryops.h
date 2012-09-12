#ifndef QUERYOPS_H 
#define QUERYOPS_H

#include "types.h"

//Function prototypes
querydata* createQuery(int sesnum, int seqnum, char* data_r, Bool encode);


char* encodeQuery(querydata*);

querydata* decodeResponse(char* url);

char* decodeData (char* s);
char* encodeData (char* s, int bufSize);
char* createGarbage(int length);

Bool inOrder(querydata*, querydata*);

//Debug and helper routines
char *replace_str(char*, char*, char*);
void printQuery(querydata*);

#endif