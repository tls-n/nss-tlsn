#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "nspr.h"
#include "plgetopt.h"
#include "prerror.h"
#include "prnetdb.h"

#include "nss.h"
#include "ssl.h"
#include "sslproto.h"
#include <pk11func.h>
#include <time.h>
#include "tlsproofstr.h"

#define SHA_256_LENGTH 32

int evidenceReceived = 0;

/*Error handler*/
void error(const char *msg)
{
	PRErrorCode perr = PR_GetError();
	const char *errString = PORT_ErrorToString(perr);

	printf("!! ERROR function name: %s returned error %d:\n%s\n",msg, perr, errString);
	exit(1);
}

/*Callback function that return the password of the certificate database.
 * It is set when configuring NSS.*/
char* getPwd(PK11SlotInfo *slot, PRBool retry, void *arg){
	printf("Pass retrieved \n");

	char *pwd= NULL;
	pwd = PORT_Strdup("");

	return pwd;
}


SECStatus fetchTLSProofCallBack(unsigned char *proof, unsigned int length){
	int i;
//	printf("GOT PROOF\n");
	
	for(i=0; i < length; ++i){
		putchar(proof[i]);
	}
	return SECSuccess;
}


int main(int argc, char *argv[])
{
    PRFileDesc* socketfd = NULL;
    PRHostEnt host;
    PRNetAddr addr;
    SECStatus rv;
    PRStatus pr;
    char buffer[65536];
    char buffParam[256];
    int n;
    PRSocketOptionData  socketOption;
    SSLVersionRange ver;
	char* pathstr;
	int proof_type;
    
    // 3 arguments are necessary for the client
    if(argc < 3){
        error("Specify URL and proof_type.");
    }
	pathstr = argv[1];
	proof_type = atoi(argv[2]);
	if(proof_type != 0 && proof_type != 1 && proof_type != 2){
		error("Invalid proof_type.");
	}

    //Set the password callback
    PK11_SetPasswordFunc(getPwd);
    
    //Init
    rv = NSS_Init("../client_db");
    if(rv != SECSuccess) error("NSS_Init");
    
     //Open
	socketfd = PR_OpenTCPSocket(PR_AF_INET);
	if (socketfd == NULL) error("PR_OpenTCPSocket");


	//Set socket option
	socketOption.option = PR_SockOpt_Nonblocking;
	socketOption.value.non_blocking = PR_FALSE;
	pr = PR_SetSocketOption(socketfd, &socketOption);
	if (pr != PR_SUCCESS) error("PR_SetSocketOption");

	//Import
	socketfd = SSL_ImportFD(NULL, socketfd);
	if (socketfd == NULL) error("SSL_ImportFD");

	//Set server mode
	rv = SSL_OptionSet(socketfd, SSL_HANDSHAKE_AS_CLIENT, PR_TRUE);
	if(rv != SECSuccess) error("SSL_OptionSet, SSL_HANDSHAKE_AS_CLIENT ");

	rv = SSL_OptionSet(socketfd, SSL_ENABLE_TLS_PROOF, PR_TRUE);
	if(rv != SECSuccess) error("SSL_OptionSet, SSL_ENABLE_TLS_PROOF");
	fprintf(stderr, "TLS-N enabled\n");
	//Set the proof return callback
	if(proof_type == 0){
		rv = SSL_TLSProofSetReturnCallBack(socketfd, fetchTLSProofCallBack, hidden_plaintext_proof);
	}else if(proof_type == 1){
		rv = SSL_TLSProofSetReturnCallBack(socketfd, fetchTLSProofCallBack, plaintext_proof);
	}else if(proof_type == 2){
		rv = SSL_TLSProofSetReturnCallBack(socketfd, fetchTLSProofCallBack, plaintext_proof | omit_cert_chain);
	}
	if(rv != SECSuccess) error("SLL_TLSProofSetReturnCallBack");

    //Set the chunk size
    PRUint16 chunk_size;
	if(proof_type == 0){
		chunk_size = 8;
	}else if(proof_type == 1 || proof_type == 2){
		chunk_size = 65535;
	}
    rv = SSL_TLSProofSetChunkSize(socketfd, chunk_size);
    if(rv != SECSuccess) error("SSL_TLSProofSetChunkSize");

	//Set url for authentication
	rv = SSL_SetURL(socketfd, "tls-n.org");
	if(rv != SECSuccess) error("SSL_SetURL");

	//Force TLS 1.3
	ver.max= SSL_LIBRARY_VERSION_TLS_1_3;
	ver.min= SSL_LIBRARY_VERSION_TLS_1_3;
	rv = SSL_VersionRangeSet(socketfd,&ver);
	if(rv != SECSuccess) error("SSL_VersionRangeSet");

	//Get host
	pr = PR_GetHostByName("129.132.15.113",buffParam,256,&host);
	if (pr != PR_SUCCESS) error("PR_GetHostByName");
	rv = PR_EnumerateHostEnt(0, &host, 443, &addr);
	if(rv < 0) error("PR_EnumerateHostEnt");

	//Connect
	pr = PR_Connect(socketfd, &addr, PR_INTERVAL_NO_TIMEOUT);
	if(pr != PR_SUCCESS) error("PR_Connect");

	PRBool val = PR_FALSE;

	//Send one request to establish session
	snprintf(buffer, sizeof(buffer), "GET %s HTTP/1.1\r\nHost: tls-n.org\r\nConnection: keep-alive\r\n\r\n", pathstr);
//	printf("%s", buffer);
	n = PR_Write(socketfd,buffer,strlen(buffer));
	if (n < 0) {
		error("ERROR writing to socket");
	}
	
	//See if the negotiation of TLS proof was successful
	rv = SSL_TLSProofIsNegociated(socketfd,&val);
	if(rv != SECSuccess) error("SSL_TLSProofIsNegociated");
	
	//Get the TLS version used
	rv = SSL_VersionRangeGet(socketfd,&ver);
	if(rv != SECSuccess) error("SSL_VersionRangeGet");
	
	n = 1;
	while(n != 0){
		n = PR_Read(socketfd, buffer, sizeof(buffer));
//		printf("Reading...: %i\n", n);
//		printf(buffer);

	}

    rv = SSL_TLSProofRequestProof(socketfd);
    if(rv != SECSuccess) error("SSL_TLSProofRequestProof");


//	printf("Reading...: %i\n", n);
	PR_Read(socketfd, buffer, sizeof(buffer));

//	printf("Done...\n");

    PR_Close(socketfd);

    return 0;
}

