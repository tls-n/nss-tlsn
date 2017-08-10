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
#include "tlsproofstr.h"
#include "prio.h"
#include "pk11func.h"


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


int main(int argc, char *argv[])
{
	unsigned char buffer[65536*16];

	// Hack to enable environment variables
	SSL_OptionSetDefault(SSL_ENABLE_TLS_PROOF, PR_TRUE);


	// 2 arguments are necessary for the client
	if(argc < 2){
		error("Specify proof file.");
	}

	//Set the password callback
	PK11_SetPasswordFunc(getPwd);

	//Init
	SECStatus rv = NSS_Init("../client_db");
	if(rv != SECSuccess) error("NSS_Init");

	PRFileDesc* fd = PR_Open(argv[1], PR_RDONLY, 0);
	
	int length = PR_Read(fd, buffer, sizeof(buffer));
	assert(PR_Read(fd, buffer, sizeof(buffer)) == 0);

	if(SSL_TLSProofCheckProof(buffer, length) == SECSuccess){
		printf("Proof successfully verified!\n");
	} else {
		printf("Proof is incorrect\n");
	}		
	printf("\nEND\n");
	return 0;
}

