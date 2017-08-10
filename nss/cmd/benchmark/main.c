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
#define RUNS 100

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
	printf("Got proof of size: %i\n", length);
	if(SSL_TLSProofCheckProof(proof, length) == SECSuccess){
		printf("Proof successfully verified!\n");
	} else {
		printf("Proof is incorrect\n");
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
    int extension_on;
    PRSocketOptionData  socketOption;
    SSLVersionRange ver;
    
    // 3 arguments are necessary for the client
    if(argc < 4){
        error("Specify host, port and whether the extension is on (1) or off (0)");
    }
    extension_on = atoi(argv[3]);
    //Set the password callback
    PK11_SetPasswordFunc(getPwd);
    
    //Init
    rv = NSS_Init("../client_db");
    if(rv != SECSuccess) error("NSS_Init");
    
    int response_size = 10;
    for(int i=0 ; i < 7 ; i++)
    {
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
    
        if (extension_on) {
        //Enable TLS Proof extension for non-repudiation
            rv = SSL_OptionSet(socketfd, SSL_ENABLE_TLS_PROOF, PR_TRUE);
            if(rv != SECSuccess) error("SSL_OptionSet, SSL_ENABLE_TLS_PROOF");
            fprintf(stderr, "TLS-N enabled\n");
            //Set the proof return callback
            rv = SSL_TLSProofSetReturnCallBack(socketfd, fetchTLSProofCallBack, hidden_plaintext_proof);
            if(rv != SECSuccess) error("SLL_TLSProofSetReturnCallBack");
        } else {
            rv = SSL_OptionSet(socketfd, SSL_ENABLE_TLS_PROOF, PR_FALSE);
            if(rv != SECSuccess) error("SSL_OptionSet, SSL_ENABLE_TLS_PROOF");
            fprintf(stderr, "TLS-N disabled\n");
        }
    
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
    
        PRBool val = PR_FALSE;

        //Send one request to establish session
        snprintf(buffer, sizeof(buffer), "GET /%d.txt HTTP/1.1\nHost: tls-n.testserver\n\n", response_size);
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
        
        //Read an incoming message
        char current = '\0';
        char last = '\0';
        int header_size = 0;
        while (!(current=='\n' && last=='\n')) {
            if (current != '\r') {
                last = current;
            }
            n = PR_Read(socketfd,&current,1);
            //printf("%x ",current);
            header_size++;
            if (n<=0) break;
        }
        n = 0;
        int n_read = 1; 
        while (n < response_size && n_read > 0) {
            bzero(buffer,sizeof(buffer));
            n_read = PR_Read(socketfd,buffer,sizeof(buffer));
            n += n_read;
        }
        if (n < 0){
            error("ERROR reading from socket");
        }
        if (n == 0){
            error("socket closed prematurely");
        }
        //printf("\nheader size: %d\n", header_size);
        double times[RUNS];
        for (int j=0; j<RUNS; j++){
            
            /* sleep */
            struct timespec sleep_time;
            struct timespec rem;
            sleep_time.tv_sec = (i>=6);
            sleep_time.tv_nsec = 100000000;
            nanosleep(&sleep_time, &rem);
    
            snprintf(buffer, sizeof(buffer), "GET /%d.txt HTTP/1.1\nHost: tls-n.testserver\n\n", response_size);
            
            struct timespec start;
            clock_gettime(CLOCK_REALTIME, &start);
            //Send request
            n = PR_Write(socketfd,buffer,strlen(buffer));
            if (n < 0) {
                error("ERROR writing to socket");
                    }
        
            //Read an incoming message
            current = '\0';
            last = '\0';
            while (!(current=='\n' && last=='\n')) {
                if (current != '\r') {
                    last = current;
                }
                n = PR_Read(socketfd,&current,1);
                if (n<=0) break;
            }
            n = 0;
            n_read = 1; 
            while (n < response_size && n_read > 0) {
                bzero(buffer,sizeof(buffer));
                n_read = PR_Read(socketfd,buffer,sizeof(buffer));
                n += n_read;
                //printf("%d\n",n);
            }
            if (n_read == 0){
                error("socket closed prematurely");
            }
            if (n_read < 0){
                printf("response_size: %d\trun: %d\n",response_size, j);
                error("ERROR reading from socket");
            }
            //printf("\n");
            struct timespec end;
            clock_gettime(CLOCK_REALTIME, &end);
            long long diff = (end.tv_sec - start.tv_sec)*1000000000 + end.tv_nsec - start.tv_nsec;
            double diff_s = ((double) diff)/1000000000.0;
            times[j] = diff_s;
            //printf("Time: %f seconds", diff_s);
    
        }
        printf("%d", response_size);
        for(int j=0;j<RUNS;j++) {
            printf(", %f", times[j]);
        }
        printf("\n");
        fflush(stdout);
        response_size = response_size*10;
        PR_Close(socketfd);
    }
    return 0;
}

