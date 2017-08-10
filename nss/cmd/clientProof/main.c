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
#include "tlsproofstr.h"
#include <pk11func.h>

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
/*Add a message to the Merkle tree
 * message is the input message and len the length
 * This function print the input and output of the hash functions. */
void saveMessage(char* message, unsigned int len)
{
	SECStatus rv;
	PK11Context *ctx = NULL;
	unsigned char *hashMessage = NULL;
	unsigned int outLen =0;
	hashMessage = malloc(32*sizeof(char));

	printf("\nInput =>[");
	for(int i = 0; i < len; i++) printf("%02x", message[i]);
	printf("] = '");
	for(int i = 0; i < len; i++) if(message[i]!= 0x0a) printf("%c", message[i]);
	printf("'\n");

	//Hash the input message
	ctx = PK11_CreateDigestContext(SEC_OID_SHA256);
	if (!ctx) error("PK11_CreateDigestContext");
	rv = PK11_DigestBegin(ctx);
	if(rv != SECSuccess) error("PK11_DigestBegin");
	rv = PK11_DigestOp(ctx,(unsigned char*)message,len);
	if(rv != SECSuccess) error("PK11_DigestOp");
    rv = PK11_DigestFinal(ctx,hashMessage,&outLen,SHA_256_LENGTH);

    printf("Message Hash=>[");
    for(int i = 0; i < outLen; i++) printf("%02x", hashMessage[i]);
        		printf("]\n");

 	printf("Input =>[");
    for(int i = 0; i < SHA_256_LENGTH; i++) printf("%02x", merkleRoot[i]);
    for(int i = 0; i < SHA_256_LENGTH; i++) printf("%02x", hashMessage[i]);
    printf("]\n");

    //Hash the actual Merkle root with the previous computed hash
    ctx = PK11_CreateDigestContext(SEC_OID_SHA256);
    if (!ctx) error("PK11_CreateDigestContext");
    rv = PK11_DigestBegin(ctx);
    if(rv != SECSuccess) error("PK11_DigestBegin");
    rv = PK11_DigestOp(ctx,merkleRoot,SHA_256_LENGTH);
    if(rv != SECSuccess) error("PK11_DigestOp");
    rv = PK11_DigestOp(ctx,hashMessage,SHA_256_LENGTH);
    if(rv != SECSuccess) error("PK11_DigestOp");
    rv = PK11_DigestFinal(ctx,hashMessage,&outLen,SHA_256_LENGTH);

    printf("New Root=>[");
        for(int i = 0; i < outLen; i++) printf("%02x", hashMessage[i]);
            		printf("]\n\n");

    //Update the Merkle root with the new hash
    memcpy(merkleRoot,hashMessage,SHA_256_LENGTH);

	return;
}


SECStatus fetchTLSProofCallBack(unsigned char *proof, unsigned int length){
	printf("Got proof of size: %i\n", length);
	if(SSL_TLSProofCheckProof(proof, length) == SECSuccess){
		printf("Proof successfully verified!\n");
	} else {
		printf("Proof is incorrect\n");
	}		
	PORT_Free(proof);
	exit(0);
	return SECSuccess;
}




/*This is set when configuring TLS proof
 * It will be called by NSS when it receive a signature from the server. */
SECStatus myTLSPRoofCallBack(PRFileDesc *fd, unsigned char *signature, unsigned int length)
{
	SECItem sigItem;
	sigItem.len = length;
	sigItem.data = signature;
	CERTCertificate *cert = NULL;
	cert = PK11_FindCertFromNickname("tls-n.testserver",NULL); assert(cert);
	SECKEYPublicKey *pubKey = NULL;
	pubKey = CERT_ExtractPublicKey(cert); assert(pubKey);
	SECStatus rv;
	FILE *sigFile = fopen("sig.txt", "w");

	printf("Proof received ! Contain the following signature :\n");

	printf("[");
	for(int i = 0; i < length; i++) printf("%02x", signature[i]);
	printf("]\n");

	//Save the signature in a file
	for(int i = 0; i < length; i++) fprintf(sigFile,"%x", signature[i]);
	fclose(sigFile);

	//Read the message file
	printf("\nPress enter to verify the signature ...");
	while(getchar()!= '\n');
	printf("Generate Merkle root from file...\n");
	unsigned char c = 0x00;
	int l = 0;
	char buffer[256];
	FILE *mess;
	mess = fopen("messages.txt", "r");

	if(!mess) return SECFailure;

	while(c != 0xff){
		c = getc(mess);
		buffer[l] = c;
		l++;

		if(l >= 256) return SECFailure;

		if(c == 0x0a){
			//Add message to hash chain
			saveMessage(buffer,l);
			l = 0;
		}
	}

	//Verify signature over the Merkle root
	SECItem data;
	data.type = siBuffer;
	data.data = merkleRoot;
	data.len = SHA_256_LENGTH;

	rv = PK11_Verify(pubKey, &sigItem, &data, NULL);

	printf("Verification of the signature: =>[%i] (0 = valid -1 = invalid)\n",(int)rv);



	return SECSuccess;
}

int main(int argc, char *argv[])
{
	PRFileDesc* socketfd = NULL;
	PRHostEnt host;
	PRNetAddr addr;
	SECStatus rv;
	PRStatus pr;
	char buffer[1024];
	char buffParam[256];
	int n;
	PRSocketOptionData  socketOption;
	SSLVersionRange ver;

	//Initialize the original Merkle root (root of the Merkle root) to "000..."
	for(int i=0;i < SHA_256_LENGTH;i++) merkleRoot[i] = 0;

	messagesFile = fopen("messages.txt", "w");

	// 3 arguments are necessary for the client
	if(argc < 3){
		error("Specify host and port");
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

	//Force TLS 1.3
    ver.max= SSL_LIBRARY_VERSION_TLS_1_3;
    ver.min= SSL_LIBRARY_VERSION_TLS_1_3;
    rv = SSL_VersionRangeSet(socketfd,&ver);
    if(rv != SECSuccess) error("SSL_VersionRangeSet");

	//Enable TLS Proof extension for non-repudiation
	rv = SSL_OptionSet(socketfd, SSL_ENABLE_TLS_PROOF, PR_TRUE);
	if(rv != SECSuccess) error("SSL_OptionSet, SSL_ENABLE_TLS_PROOF");

	//Set the proof return callback
	rv = SSL_TLSProofSetReturnCallBack(socketfd, fetchTLSProofCallBack, hidden_plaintext_proof);
	if(rv != SECSuccess) error("SSL_TLSProofSetReturnCallBack");

	//Set url for authentication
	rv = SSL_SetURL(socketfd, "tls-n.testserver");
	if(rv != SECSuccess) error("SSL_SetURL");

	//Get host
	pr = PR_GetHostByName(argv[1],buffParam,256,&host);
	if (pr != PR_SUCCESS) error("PR_GetHostByName");
	rv = PR_EnumerateHostEnt(0, &host, atoi(argv[2]), &addr);
	if(rv < 0) error("PR_EnumerateHostEnt");

	//Connect
	pr = PR_Connect(socketfd, &addr, PR_INTERVAL_NO_TIMEOUT);
	if(pr != PR_SUCCESS) error("PR_Connect");

	PRBool val = PR_FALSE;

	/*Our client will ask 3 times for some user input before terminating the exchange*/
	for(int i=0 ; i < 3 ; i++)
	{
		printf("\nPlease enter the message: \n");
		fgets(buffer,sizeof(buffer)-1,stdin);
		/*Send the previously typed message
		 * Note that when doing the first Write NSS will triger the Handshake
		 * n is the number of packet sent*/
		n = PR_Write(socketfd,buffer,strlen(buffer));
		if (n < 0)
			error("ERROR writing to socket");

		//Update the merkle root and save the sent message
		//saveMessage(buffer,n);
		for(int i = 0; i < n; i++) fprintf(messagesFile,"%c", buffer[i]);


		//See if the negotiation of TLS proof was successful
		rv = SSL_TLSProofIsNegociated(socketfd,&val);
		if(rv != SECSuccess) error("SSL_TLSProofIsNegociated");

		//Get the TLS version used
		rv = SSL_VersionRangeGet(socketfd,&ver);
		if(rv != SECSuccess) error("SSL_VersionRangeGet");

		/* Print the TLS version negotiated, for TLS 1.3 it should show [304:304] and if TLS proof was
		 * successfully negotiated */
		printf("\nNew message ! Protocol[%x:%x], TLS Proof enable[%i] :\n",ver.min,ver.max,(int)val);

		//Read an incoming message
		bzero(buffer,sizeof(buffer));
		n = PR_Read(socketfd,buffer,sizeof(buffer));
		if (n < 0)
			error("ERROR reading from socket");
		printf("%s",buffer);

		//Update the merkle root and save the received message
		//saveMessage(buffer,n);
		for(int i = 0; i < n; i++) fprintf(messagesFile,"%c", buffer[i]);
	}

	//Request the proof, NSS will call the associated callback when the proof arrive
	rv = SSL_TLSProofRequestProof(socketfd);
	if(rv != SECSuccess) error("SSL_TLSProofRequestProof");

	fclose(messagesFile);

	//This is necessary to get the signature but will never return
	PR_Read(socketfd,buffer,255);

	PR_Close(socketfd);


	printf("\nEND\n");
	return 0;
}

