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

#include "hasht.h"
#include "alghmac.h"
#include "sechash.h"
#include <pk11func.h>

#define SHA_256_LENGTH 32

/*Error handler*/
void error(const char *msg)
{
    PRErrorCode perr = PR_GetError();
    const char *errString = PORT_ErrorToString(perr);

    printf("!! ERROR function name: %s returned error %d:\n%s\n",msg, perr, errString);
    exit(1);
}

#define SHA512_BLOCK_LENGTH 128
#define HASH_BLOCK_LENGTH_MAX SHA512_BLOCK_LENGTH
#define HMAC_PAD_SIZE HASH_BLOCK_LENGTH_MAX

struct HMACContextStr {
    void *hash;
    const SECHashObject *hashobj;
    PRBool wasAllocated;
    unsigned char ipad[HMAC_PAD_SIZE];
    unsigned char opad[HMAC_PAD_SIZE];
};


SECStatus
my_HMAC_Init(HMACContext *cx, const SECHashObject *hash_obj,
          const unsigned char *secret, unsigned int secret_len, PRBool isFIPS)
{
    unsigned int i;
    unsigned char hashed_secret[HASH_LENGTH_MAX];

    /* required by FIPS 198 Section 3 */
    if (isFIPS && secret_len < hash_obj->length / 2) {
        return SECFailure;
    }
    if (cx == NULL) {
        return SECFailure;
    }
    cx->wasAllocated = PR_FALSE;
    cx->hashobj = hash_obj;
    cx->hash = cx->hashobj->create();
    if (cx->hash == NULL)
        goto loser;

    if (secret_len > cx->hashobj->blocklength) {
        cx->hashobj->begin(cx->hash);
        cx->hashobj->update(cx->hash, secret, secret_len);
        PORT_Assert(cx->hashobj->length <= sizeof hashed_secret);
        cx->hashobj->end(cx->hash, hashed_secret, &secret_len,
                         sizeof hashed_secret);
        if (secret_len != cx->hashobj->length) {
            goto loser;
        }
        secret = (const unsigned char *)&hashed_secret[0];
    }

    PORT_Memset(cx->ipad, 0x36, cx->hashobj->blocklength);
    PORT_Memset(cx->opad, 0x5c, cx->hashobj->blocklength);

    /* fold secret into padding */
    for (i = 0; i < secret_len; i++) {
        cx->ipad[i] ^= secret[i];
        cx->opad[i] ^= secret[i];
    }
    PORT_Memset(hashed_secret, 0, sizeof hashed_secret);
    return SECSuccess;

loser:
    PORT_Memset(hashed_secret, 0, sizeof hashed_secret);
    if (cx->hash != NULL)
        cx->hashobj->destroy(cx->hash, PR_TRUE);
    return SECFailure;
}


HMACContext *
my_HMAC_Create(const SECHashObject *hash_obj, const unsigned char *secret,
            unsigned int secret_len, PRBool isFIPS)
{
    SECStatus rv;
    HMACContext *cx = PORT_ZNew(HMACContext);
    if (cx == NULL)
        return NULL;
    rv = my_HMAC_Init(cx, hash_obj, secret, secret_len, isFIPS);
    cx->wasAllocated = PR_TRUE;
    if (rv != SECSuccess) {
        PORT_Free(cx); /* contains no secret info */
        cx = NULL;
    }
    return cx;
}



int main(int argc, char *argv[])
{
	PRUint8 key_block[32];
	PRUint32 len = sizeof(key_block);
	char* prk = "01234567890abcdef01234567890abcdef";
	char* prk2 = "11234567890abcdef01234567890abcdef";
	PRUint32 prkLen =  32;
	PRUint32 hashLen =  32;
	char* message = "Huhu";
	int i;

    //Init
    SECStatus rv = NSS_Init("../client_db");
    if(rv != SECSuccess) error("NSS_Init");

				printf("%i\n",HASH_GetHashObject(4)->length);
		

                HMACContext *hmac = PORT_ZNew(HMACContext);
				
				hmac->wasAllocated = PR_FALSE;
                HMAC_Init(hmac, HASH_GetHashObject(4), (PRUint8 *) prk, prkLen, 0);
                HMAC_Begin(hmac);
                HMAC_Update(hmac, (PRUint8 *) message, strlen(message));
                HMAC_Finish(hmac, key_block, &len, hashLen);

        char hexbuf[2 *len+1];
        for(i = 0; i < len; ++i){
            snprintf(hexbuf + 2*i, sizeof(hexbuf), "%02x", key_block[i]);
        }

	printf("%s\n", hexbuf);

				HMAC_Init(hmac, HASH_GetHashObject(4), (PRUint8 *) prk2, prkLen, 0);
                HMAC_Begin(hmac);
                HMAC_Update(hmac, (PRUint8 *) message, strlen(message));
                HMAC_Finish(hmac, key_block, &len, hashLen);


        for(i = 0; i < len; ++i){
            snprintf(hexbuf + 2*i, sizeof(hexbuf), "%02x", key_block[i]);
        }

	printf("%s\n", hexbuf);

				HMAC_Init(hmac, HASH_GetHashObject(4), (PRUint8 *) prk, prkLen, 0);
                HMAC_Begin(hmac);
                HMAC_Update(hmac, (PRUint8 *) message, strlen(message));
                HMAC_Finish(hmac, key_block, &len, hashLen);


        for(i = 0; i < len; ++i){
            snprintf(hexbuf + 2*i, sizeof(hexbuf), "%02x", key_block[i]);
        }

	printf("%s\n", hexbuf);


                HMAC_Destroy(hmac, PR_FALSE);
				free(hmac);
	printf("\nEND\n");
	return 0;
}

