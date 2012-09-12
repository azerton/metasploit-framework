#include "types.h"

#include "queryops.h"
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

querydata* createQuery(int sesnum, int seqnum, char* data_r, Bool encode){

	querydata* qd = (querydata*)malloc(sizeof(querydata));
	
	qd->sesnum = sesnum;
	qd->seqnum = seqnum;

	qd->data = data_r;
	qd->rand = createGarbage(2); 
	qd->encode = encode;
	
	return qd;
}


/*
*	Converts the query data to a URL, ready to be send as
	a request over DNS.
*/
char* encodeQuery(querydata* qd){
	char* url = (char*)malloc(512*sizeof(char));
	char buf[5];

	url[0] = '\0';

	strcat(url, _itoa(qd->sesnum, buf, 10));
	strcat(url, ".");
	strcat(url, _itoa(qd->seqnum, buf, 10));
	strcat(url,".");
	strcat(url, qd->rand);
	strcat(url,".");

	if(qd->encode == TRUE){
		strcat(url,encodeData(qd->data, strlen(qd->data)));
		strcat(url,".");
		strcat(url,"DATA");
	}else{
		//There should be no nullbytes in data if we do not encode!
		strcat(url,qd->data);
	}

	strcat(url, DOMAIN);
	return url;
}

querydata* decodeResponse(char* url){
	char* data = (char*)malloc(512*sizeof(char));
	querydata* qd = (querydata*)malloc(sizeof(querydata));
	
	char* pch;
	
	data[0] = '\0';

	//printf("Going to decode URL -  %s\n", url);

	url = replace_str(url, DOMAIN, "");

	//printf("Domain cut off - %s\n", url);

	pch = strtok(url,"."); //Session ID
	qd->sesnum = atoi(pch);
	
	//printf("Session ID - %i\n", qd->sesnum);


	pch = strtok(NULL,"."); //Sequence number
	qd->seqnum = atoi(pch);
	
	//printf("Sequence number - %i \n", qd->seqnum);

	pch = strtok(NULL,"."); //garbage
	qd->rand = pch;
	
	pch = strtok(NULL,"."); //First data field

	while (pch != NULL){
		strcat(data,pch);
		pch = strtok(NULL, ".");
  }


  qd->bufSize = strlen(data) / 2;

  //TODO MAKE ACCORDING TO BUFSIZE
  qd->data = (char*)malloc(512*sizeof(char));

  memcpy(qd->data, decodeData(data), qd->bufSize);
  qd->data[qd->bufSize] = '\0';

  free(pch);
  free(data);
	
  return qd;

}

char* createGarbage(int length){
	char* garbage = (char*)malloc(length * sizeof(char)+1);
	char* alphabeth = "0123456789";

	int i;
	int iNumber;

	for(i = 0 ; i < length ; ++i ){	
		iNumber = rand()%10;
		garbage[i] = alphabeth[iNumber];
	} 
	
	garbage[length] = '\0';
	return garbage;
}

/*
Netbios encoding and decoding routines
The splitLabels argument allows to split labels automatically every 60 bytes.
*/
char* encodeData (char *plain, int bufSize){
	
	char* encoded = (char*)malloc(512*sizeof(char));
	
	char firstNibble[2];
	char secondNibble[2];

	int label_counter = 0;
	int i;
	
	encoded[0] = '\0';

	for( i = 0 ; i < bufSize ; i++){

		/*Check if we need to start a new label or not.
		Every DNS record label can only have 60 characters acording to the RFC.
		*/

		if(label_counter > 0 && label_counter % 60 == 0){
			strcat(encoded, ".");
			label_counter = 0;
		}else{
			label_counter = label_counter + 2;
		}

		firstNibble[0] = (char)((plain[i] >> 4) + 0x41);
		secondNibble[0] = (char)((plain[i] & 0xF) + 0x41);

		firstNibble[1] = '\0';
		secondNibble[1] = '\0';

		//Append the new characters to the result.
		strcat(encoded, firstNibble);
		strcat(encoded, secondNibble);
	}	
	
	return encoded;
}


char* decodeData (char* raw){
	char* decoded = (char*)malloc(512*sizeof(char));
	char tmpRes;

	int counter = 0;
	int bufLen = 0;
	unsigned int i;

	char first_nibble;
	char second_nibble;
	
	decoded[0] = '\0';

	for(i = 0 ; i < strlen(raw) ; i++){
		//Check if delimiter
		if(raw[i] == '.'){
			continue;
		}
		if(counter % 2 == 0){
			first_nibble = (char)(raw[i] - 0x41);
		}else{
			second_nibble = (char)(raw[i] - 0x41);
		}

		counter = counter + 1;

		if(counter >= 1  && counter % 2 ==0){
			tmpRes = (char)((first_nibble << 4) | second_nibble);
			memcpy(decoded+ bufLen, &tmpRes, 1);
			bufLen++;
		}

	}	

	return decoded;
}

Bool inOrder(querydata* qd1, querydata* qd2){
	if(qd1->seqnum == qd2->seqnum){
		return TRUE;
	}else{
		return FALSE;
	}
}

/*
* Helper and debug routines
*/
char *replace_str(char *str, char *orig, char *rep)
{
  static char buffer[4096];
  char *p;

  if(!(p = strstr(str, orig)))  // Is 'orig' even in 'str'?
    return str;

  strncpy(buffer, str, p-str); // Copy characters from 'str' start to 'orig' st$
  buffer[p-str] = '\0';

  sprintf(buffer+(p-str), "%s%s", rep, p+strlen(orig));

  return buffer;
}

void printQuery(querydata* qd){
	printf("Session ID  : %i\n", qd->sesnum);
	printf("Query seq   : %i\n", qd->seqnum);
	printf("Garbage     : %s\n", qd->rand);
	printf("Encode?     : %i\n", qd->encode);
	printf("Query data  : %s\n", qd->data);
}
