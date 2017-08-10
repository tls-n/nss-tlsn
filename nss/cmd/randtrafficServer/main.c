#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>

#include "nspr.h"
#include "plgetopt.h"
#include "prerror.h"
#include "prnetdb.h"

#include "nss.h"
#include "ssl.h"
#include "sslproto.h"
#include <pk11func.h>
#include <errno.h>
#include "secitem.h"

 #define max(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a > _b ? _a : _b; })

 #define min(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a < _b ? _a : _b; })



//Global variable
SECKEYPrivateKey *privKey = NULL; //Private key of the server certificate
CERTCertificate *cert = NULL; //Certificate of the server


void error(const char *msg)
{
	PRErrorCode perr = PR_GetError();
	const char *errString = PORT_ErrorToString(perr);

	printf("!!!!!ERROR function name: %s returned error %d:!!!!!\n%s\n",msg, perr, errString);
    exit(1);
}
/*Callback function that return the password of the certificate database.
 * It is set when configuring NSS.*/
char* getPwd(PK11SlotInfo *slot, PRBool retry, void *arg){

	char *pwd= NULL;
	pwd = PORT_Strdup("");

	return pwd;
}
/*Called when a client is connected to server*/
int accept_connection(PRFileDesc * sock, long int traffic_size)
{
	char buffer[131072];
	PRBool val;
	SSLVersionRange ver;
	SECStatus rv;
	long int handled = 0;

	while(handled < traffic_size){
		handled += PR_Read(sock, buffer, min(traffic_size, sizeof(buffer)));
	}
				//See if the negotiation of TLS proof was successful
				rv = SSL_TLSProofIsNegociated(sock,&val);
				if(rv != SECSuccess) error("SSL_TLSProofIsNegociated");

				//Get the TLS version used
				rv = SSL_VersionRangeGet(sock,&ver);
				if(rv != SECSuccess) error("SSL_VersionRangeGet");

    PR_Read(sock ,buffer,sizeof(buffer));
    PR_Close(sock);

    printf("END\n");
    return 0;

}


int main(int argc, char *argv[])
{


	PRFileDesc* listenSocket = NULL;
	PRStatus pr;
	SECStatus rv;
	char *tmp = NULL;
	PRFileDesc* newSocket = NULL;
	char* certName = "tls-n.testserver";
	PRNetAddr addr, clientAddr;
	SSLVersionRange ver;



	if(argc < 3){
			error("Specify port, traffic size");
	}
	long int traffic_size = atol(argv[2]);

	//Cache config
	tmp = PR_GetEnvSecure("TMP");
	if (!tmp){
		tmp = PR_GetEnvSecure("TMPDIR");
		tmp = PR_GetEnvSecure("TEMP");
	}
	rv = SSL_ConfigServerSessionIDCache(0,0, 0, tmp);
	if (rv != SECSuccess)
		error("SSL_ConfigServerSessionIDCache");

	//Set Password
	PK11_SetPasswordFunc(getPwd);

	rv = NSS_Init("../server_db");
	if(rv != SECSuccess)
		error("NSS_Initialize");

	//Retrieve certificate
	cert = PK11_FindCertFromNickname(certName,NULL);
	if (cert == NULL)
	error("PK11_FindCertFromNickname");

	//Retrieve private key
	privKey = PK11_FindKeyByAnyCert(cert,NULL);
	if (privKey == NULL)
		error("PK11_FindKeyByAnyCert");

	//New socket
	listenSocket = PR_OpenTCPSocket(PR_AF_INET);
	if (listenSocket == NULL) {
		error("Error: PR_NewTCPSocket");
	}

	//Server parameters
	addr.inet.ip = PR_INADDR_ANY;
	addr.inet.port = PR_htons(atoi(argv[1]));
	addr.inet.family = PR_AF_INET;

	//Bind
	pr = PR_Bind(listenSocket, &addr);
	if (pr != PR_SUCCESS) {
			error("PR_Bind");
	}


	//Listen
	pr = PR_Listen(listenSocket, 5);
	if (pr != PR_SUCCESS) {
			error("PR_Listen");
	}


	//Import to SSL
	listenSocket = SSL_ImportFD(NULL, listenSocket);
	if (listenSocket == NULL) error("SSL_ImportFD");



	//Set certificate and private key
	rv = SSL_ConfigSecureServer(listenSocket,cert, privKey, NSS_FindCertKEAType(cert));
	if (rv != SECSuccess) error("SSL_ConfigSecureServer");

	//Enable TLS Proof extension for non-repudiation
	rv = SSL_OptionSet(listenSocket, SSL_ENABLE_TLS_PROOF, PR_TRUE);
	if(rv != SECSuccess) error("SSL_OptionSet, SSL_ENABLE_TLS_PROOF");

	//Force TLS 1.3
	ver.max= SSL_LIBRARY_VERSION_TLS_1_3;
	ver.min= SSL_LIBRARY_VERSION_TLS_1_3;
	rv = SSL_VersionRangeSet(listenSocket,&ver);
	if(rv != SECSuccess) error("SSL_VersionRangeSet");

	printf("Server started ! \nListening ... \n");

	//Accept
	newSocket = PR_Accept(listenSocket, &clientAddr, PR_INTERVAL_NO_TIMEOUT);
	PR_Close(listenSocket);
	if(newSocket == 0){
		error("PR_Accept");
	}



	//Continue
	accept_connection(newSocket, traffic_size);


	return 0;
}
