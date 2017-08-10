#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>

#include "nspr.h"
#include "plgetopt.h"
#include "prerror.h"
#include "prnetdb.h"

#include "nss.h"
#include "ssl.h"
#include "sslproto.h"
#include "tlsproofstr.h"
#include <pk11func.h>
#include "tlsproofstr.h"

#define SHA_256_LENGTH 32

/*Global variables*/
unsigned char merkleRoot[SHA_256_LENGTH]; //Merkle root
FILE *messagesFile = NULL; // File to print the messages received and sent

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


//*
SECStatus fetchTLSProofCallBack(unsigned char *proof, unsigned int length){
	unlink("/tmp/testproof");
	int fd = open("/tmp/testproof", O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	write(fd, proof, length);
	close(fd);
	printf("Got proof of size: %i\n", length);
	if(SSL_TLSProofCheckProof(proof, length) == SECSuccess){
		printf("Proof successfully verified!\n");
		exit(0);
	} else {
		printf("Proof is incorrect\n");
		exit(1);
	}		
	return SECSuccess;
}
// */



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

	// 3 arguments are necessary for the client
	if(argc < 4){
		error("Specify host and port and chunk size");
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

	//Enable TLS Proof extension for non-repudiation
	rv = SSL_OptionSet(socketfd, SSL_ENABLE_TLS_PROOF, PR_TRUE);
	if(rv != SECSuccess) error("SSL_OptionSet, SSL_ENABLE_TLS_PROOF");

	//Set the proof return callback
	rv = SSL_TLSProofSetReturnCallBack(socketfd, fetchTLSProofCallBack, plaintext_proof);
	if(rv != SECSuccess) error("SSL_TLSProofSetReturnCallBack");

	//Set url for authentication
	rv = SSL_SetURL(socketfd, "tls-n.testserver");
	if(rv != SECSuccess) error("SSL_SetURL");

    //Set the proof return callback
    PRUint16 chunk_size = atoi(argv[3]);
    printf("Proposing chunk size: %i\n", chunk_size);
    rv = SSL_TLSProofSetChunkSize(socketfd, chunk_size);
    if(rv != SECSuccess) error("SSL_TLSProofSetChunkSize");


	//Force TLS 1.3
    ver.max= SSL_LIBRARY_VERSION_TLS_1_3;
    ver.min= SSL_LIBRARY_VERSION_TLS_1_3;
    rv = SSL_VersionRangeSet(socketfd,&ver);
    if(rv != SECSuccess) error("SSL_VersionRangeSet");

	//Get host
	pr = PR_GetHostByName(argv[1],buffParam,256,&host);
	if (pr != PR_SUCCESS) error("PR_GetHostByName");
	rv = PR_EnumerateHostEnt(0, &host, atoi(argv[2]), &addr);
	if(rv < 0) error("PR_EnumerateHostEnt");

	//Connect
	pr = PR_Connect(socketfd, &addr, PR_INTERVAL_NO_TIMEOUT);
	if(pr != PR_SUCCESS) error("PR_Connect");

	char number[10];
	int first = 1;
	int i;
	PRBool val;
    while(1){
#ifndef TRACE
            getchar();
#else
            // Get Marker
            char ch = getchar();
            assert(ch == 'H');

#endif

            char rw = getchar();
			if(rw == 'q'){
				break;
			}
            fgets(number, 7, stdin);
            int num = atoi(number);
            assert(num <= sizeof(buffer));
            // Read an incoming message
            if(rw == 'r'){
                n = PR_Read(socketfd, buffer, num);
                assert(n == num);

            }else if(rw == 'w'){
                // Write
                for(i = 0; i < num; ++i) buffer[i] = getchar();
                n = PR_Write(socketfd, buffer, num);
                assert(n == num);
            }else{
				assert(0);
			}


            if(first){
                first = 0;
                //See if the negotiation of TLS proof was successful
                rv = SSL_TLSProofIsNegociated(socketfd,&val);
                if(rv != SECSuccess) error("SSL_TLSProofIsNegociated");

                //Get the TLS version used
                rv = SSL_VersionRangeGet(socketfd,&ver);
                if(rv != SECSuccess) error("SSL_VersionRangeGet");
     
            }


	}

	//Request the proof, NSS will call the associated callback when the proof arrive
	rv = SSL_TLSProofRequestProof(socketfd);
	if(rv != SECSuccess) error("SSL_TLSProofRequestProof");

	//This is necessary to get the signature but will never return
//    PR_Write(socketfd, "a", 1);
	n = PR_Read(socketfd,buffer,sizeof(buffer));

	PR_Close(socketfd);


	printf("\nEND: %i\n", n);
	return 0;
}

