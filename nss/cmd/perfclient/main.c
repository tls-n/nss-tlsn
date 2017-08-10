#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include <unistd.h>

#include "nspr.h"
#include "plgetopt.h"
#include "prerror.h"
#include "prnetdb.h"

#include "nss.h"
#include "ssl.h"
#include "sslproto.h"
#include <pk11func.h>
/*Error handler*/
void error(const char *msg)
{
    PRErrorCode perr = PR_GetError();
    const char *errString = PORT_ErrorToString(perr);

    printf("!! ERROR function name: %s returned error %d:\n%s\n",msg, perr, errString);
    exit(1);
}



int main(int argc, char *argv[])
{
	PRFileDesc* socketfd = NULL;
	PRHostEnt host;
	PRNetAddr addr;
	SECStatus rv;
	PRStatus pr;
	char buf[16384];
	char buffParam[256];
	int n;
	PRSocketOptionData  socketOption;
	SSLVersionRange ver;
	int i, j;
	int rep;
	const int repititions = 50;
	const int stepsize = 64;

	// 3 arguments are necessary for the client
	if(argc < 3){
		error("Specify host and port");
	}

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

	//Set url for authentication
	rv = SSL_SetURL(socketfd, "tls-n.testserver");
	if(rv != SECSuccess) error("SSL_SetURL");

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

//	PRBool val = PR_FALSE;

	PRBool first = PR_TRUE; 

	srand (0);

	for(i = 1; i < 16384; i += stepsize){
		for(rep = 0; rep < repititions; ++rep){

			for (j=0; j < i; ++j){
				buf[j] = rand();
			}

			/*Send the previously typed message
			* Note that when doing the first Write NSS will triger the Handshake
			* n is the number of packet sent*/
			n = PR_Write(socketfd,buf,i);
			if (n < 0)
				error("ERROR writing to socket");
			PORT_Assert(i == n);

//			//See if the negotiation of TLS proof was successful
//			rv = SSL_TLSProofIsNegociated(socketfd,&val);
//			if(rv != SECSuccess) error("SSL_TLSProofIsNegociated");
//
//			//Get the TLS version used
//			rv = SSL_VersionRangeGet(socketfd,&ver);
//			if(rv != SECSuccess) error("SSL_VersionRangeGet");
//
//			/* Print the TLS version negotiated, for TLS 1.3 it should show [304:304] and if TLS proof was
//			* successfully negotiated */
//			printf("\nNew message ! Protocol[%x:%x], TLS Proof enable[%i] :\n",ver.min,ver.max,(int)val);
			printf("\nBla\n");

//			usleep(100000);
			// Rerun the first batch because of cpu scaling
		}
		if(first){
			first = PR_FALSE;
			i -= stepsize;
		}
	}

	PR_Close(socketfd);


	printf("\nEND\n");
	return 0;
}

