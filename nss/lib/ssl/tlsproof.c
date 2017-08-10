#include "nssrenam.h"
#include "cert.h"
#include "keyhi.h"
#include "pkcs11.h"
#include "pk11func.h"
#include "prtime.h"
#include "seccomon.h"
#include "secitem.h"
#include "secmod.h"
#include "secmodi.h"
#include "sslerr.h"
#include "ssl.h"
#include "sslimpl.h"
#include "sslproto.h"
#include "stdarg.h"
#include "tls13con.h"
#include "tls13hkdf.h"
#include "secutil.h"

#include "tlsproof.h"

#include <stdio.h>
#include <math.h>
#include <regex.h>

// Enable for Performance Measuremeants, uses [Measure] tags
//#define EV_MEASURE_COMP
#ifdef EV_MEASURE_COMP
//	#undef TRACE
#endif


char* SALT_TREE_LABEL = "TLS-NSaltTree";

PRUint8 merkle_root_marker = 0;
PRUint8 hash_chain_marker = 1;
static SECStatus tlsproof_handleMessageRequest(sslSocket *ss, sslBuffer  *origBuf);
static SECStatus tlsproof_handleMessageResponse(sslSocket *ss, sslBuffer *origBuf);


static SECStatus requires_plaintext_saving(int proof_type){
	return ((proof_type & last_message_proof) != 0) || ((proof_type & hidden_plaintext_proof) != 0)|| ((proof_type & plaintext_proof) != 0);
}

PK11SymKey* create_sym_key_for_salt(RecordProofInfo* rpi, PRUint8* keydata){
	PK11SlotInfo* slot = PK11_GetInternalKeySlot();
	SECItem keyItem;
	keyItem.data = keydata; 
	keyItem.len = rpi->salt_size; 

	/* turn the SECItem into a key object */
	PK11SymKey* sym_key = PK11_ImportSymKey(slot, CKM_AES_KEY_GEN, PK11_OriginUnwrap, CKA_ENCRYPT, &keyItem, NULL);

	return sym_key;
}


// TODO: Non-linear search  
// TODO: Change signature
static PRBool is_hidden_chunk(PRUint16* hidden_chunk_ids, PRUint16 num_hidden_chunks, PRUint16 chunk_id){
    int i;
    for(i = 0; i < num_hidden_chunks; ++i){
        if(hidden_chunk_ids[i] == chunk_id){
            return PR_TRUE;
        }
    }
    return PR_FALSE;
}

static PRUint16 get_chunk_length2(RecordProofInfo* rpi, PRUint16 chunk_index){
	if (chunk_index + 1 < rpi->num_chunks){
		return rpi->chunk_size;
	} else {			
		return rpi->record_length - rpi->chunk_size * chunk_index;
	}
}

static PRUint16 get_chunk_length(RecordProofInfo* rpi){
	return get_chunk_length2(rpi, rpi->chunk_index);
}


static SECStatus allocate_salts(RecordProofInfo* rpi){
	int i;
	rpi->salts = (PRUint8**) PORT_Alloc(sizeof(PRUint8*) * rpi->num_chunks);
	if(rpi->salts == NULL){
#ifdef TRACE
		SSL_TRC(10, ("Error! Couldn't allocate memory!"));
#endif
		return SECFailure;
	}
	// Allocate salts
	rpi->salts[0] = (PRUint8*) PORT_Alloc(rpi->salt_size * rpi->num_chunks);
	if(rpi->salts[0] == NULL){
#ifdef TRACE
		SSL_TRC(10, ("Error! Couldn't allocate memory!"));
#endif
		return SECFailure;
	}
	for(i = 1; i < rpi->num_chunks; ++i){
		rpi->salts[i] = rpi->salts[i-1] + rpi->salt_size;
	}
	return SECSuccess;
}

// TODO: Unify
static PRUint8** allocate_string_array(PRUint16 salt_size, PRUint16 num_chunks){
	int i;
	PRUint8** salts = (PRUint8**) PORT_Alloc(sizeof(PRUint8*) * num_chunks);
	salts[0] = (PRUint8*) PORT_Alloc(salt_size * num_chunks);
	if(salts[0] == NULL){
#ifdef TRACE
		SSL_TRC(10, ("Error! Couldn't allocate memory!"));
#endif
		return NULL;
	}
	for(i = 1; i < num_chunks; ++i){
		salts[i] = salts[i-1] + salt_size;
	}
	return salts;
}

static PRUint16 num_skipped_leaves(RecordProofInfo* rpi, int level, PRUint16 chunk_index){
	if(level == rpi->tree_levels){
		return 1;
	}
	if(level == 0){
		return rpi->num_chunks;
	}
	// Compute the maximal number of children
	PRUint16 max_leaves = 1 << ( rpi->tree_levels - level);
	if(max_leaves + chunk_index > rpi->num_chunks){
		// All the remaining
		PORT_Assert(rpi->num_chunks - chunk_index < rpi->num_chunks);
		return rpi->num_chunks - chunk_index;
	}else{
		// Maximum possible
		PORT_Assert(max_leaves < rpi->num_chunks);
		return max_leaves;
	}
	
}


static SECStatus free_rpi(RecordProofInfo* rpi){
	// Hack to get around the const
	PRUint8* tmp;
	
	if(rpi->salts != NULL){
		PORT_Free(rpi->salts[0]);
		PORT_Free(rpi->salts);
		rpi->salts = NULL;
	}
	if(rpi->num_hashes > 0){
		PORT_Free(rpi->hash_locs);
		rpi->hash_locs = NULL;
		if(!rpi->initialized_from_proof){
			PORT_Free(rpi->proof_merkle_hashes[0]);
		}
		PORT_Free(rpi->proof_merkle_hashes);
		rpi->proof_merkle_hashes = NULL;
		rpi->num_hashes = 0;
	}
	if(rpi->num_salts > 0){
		PORT_Free(rpi->salt_locs);
		rpi->salt_locs = NULL;
		rpi->num_salts = 0;
	}
	if(rpi->num_hidden_chunks > 0){
		PORT_Free(rpi->hidden_chunk_ids);
		rpi->hidden_chunk_ids = NULL;
		rpi->num_hidden_chunks = 0;
		// Inflated the record -> free it
		if(rpi->initialized_from_proof){
			PORT_Memcpy(&tmp, &(rpi->record), sizeof(PRUint8*));
			PORT_Free(tmp);
		}
	}
	if(rpi->ctx != NULL){
		PK11_DestroyContext(rpi->ctx, PR_TRUE);
	}

	if(rpi->hmac != NULL){
		HMAC_Destroy(rpi->hmac, PR_FALSE);
		PORT_Free(rpi->hmac);
		rpi->hmac = NULL;
	}

	if(rpi->hmac_info != NULL){
		PORT_Free(rpi->hmac_info);
	}

	PORT_Free(rpi);
	rpi = NULL;
	return SECSuccess;
}

// Inflate the record by putting 'X' where content was censored
static SECStatus inflate_record(RecordProofInfo* rpi, PRUint8* compressed_record){
	int i;
	int j;
	PRUint16 num_normal_records = 0;
	PRUint16 chunk_length;
	PRUint16 offset = 0;

	PRUint8 *record = (PRUint8*) PORT_Alloc(rpi->record_length);
	for(i = 0; i < rpi->num_chunks; ++i){
		chunk_length = get_chunk_length2(rpi, i);
		if(is_hidden_chunk(rpi->hidden_chunk_ids, rpi->num_hidden_chunks, i)){
			for(j = 0; j < chunk_length; ++j){
				// Put this for hidden chunks
				record[offset] = 'X';
				offset++;
			}
		}else{
			// Copy normal records
			PORT_Memcpy(record + offset, compressed_record + (num_normal_records * rpi->chunk_size), chunk_length);
			offset += chunk_length;
			num_normal_records++;
		}	
	}
	PORT_Assert(offset == rpi->record_length);
	rpi->record = record;
	return SECSuccess;
}

// Recompute the hidden chunks from the proof contents
static SECStatus compute_hidden_chunks_from_proof(RecordProofInfo* rpi){
	int i;
	int j;
	PRUint16 hidden_chunk_ids[rpi->num_chunks];
	PRUint16 num_skipped;
	rpi->num_hidden_chunks = 0;
	for(i = 0; i < rpi->num_hashes; ++i){	
		num_skipped = num_skipped_leaves(rpi, rpi->hash_locs[i].tree_level, rpi->hash_locs[i].chunk_index);
		for(j = 0; j < num_skipped; ++j){
			// Save all the skipped leaves as hidden
			hidden_chunk_ids[rpi->num_hidden_chunks] = rpi->hash_locs[i].chunk_index + j;
			rpi->num_hidden_chunks++;
		}
	}
	if(rpi->num_hidden_chunks == 0){
		rpi->hidden_chunk_ids = NULL;
	}else{
		rpi->hidden_chunk_ids = (PRUint16*) PORT_Alloc(rpi->num_hidden_chunks * sizeof(PRUint16));
		if(rpi->hidden_chunk_ids == NULL) return SECFailure;
		PORT_Memcpy(rpi->hidden_chunk_ids, hidden_chunk_ids, rpi->num_hidden_chunks * sizeof(PRUint16));
#ifdef TRACE
		SSL_TRC(25, ("Recomputed Hidden Chunk IDs:"));
		// TODO: Make nicer
		for(i = 0; i < rpi->num_hidden_chunks; ++i){
			SSL_TRC(25, ("%u", rpi->hidden_chunk_ids[i]));
		}
#endif
	}
	return SECSuccess;
}

// Compute the compressed record length
static PRUint16 compute_compressed_record_padding(RecordProofInfo* rpi){
	int j;
	PRBool last_censored = PR_FALSE;
	PRUint16 compressed_record_padding = 0;

	// Subtract the size for censored chunks
	for(j = 0; j < rpi->num_hidden_chunks; ++j){
		last_censored = (rpi->hidden_chunk_ids[j] == rpi->num_chunks - 1) | last_censored;
	}
	// Last chunk is a special case. If not censored, and necessary, pad it
	if(!last_censored && get_chunk_length2(rpi, rpi->num_chunks - 1) != rpi->chunk_size){
		compressed_record_padding = rpi->chunk_size - get_chunk_length2(rpi, rpi->num_chunks - 1);
	}
	
	return compressed_record_padding; 
}


// Compute the compressed record length
static PRUint16 compute_compressed_record_length(RecordProofInfo* rpi){
	int j;
	PRUint16 compressed_record_length = rpi->record_length;

	// Subtract the size for censored chunks
	for(j = 0; j < rpi->num_hidden_chunks; ++j){
		compressed_record_length -= get_chunk_length2(rpi, rpi->hidden_chunk_ids[j]);
	}
	// Add Padding if necessary
	compressed_record_length += compute_compressed_record_padding(rpi);
	
	return compressed_record_length; 
}


static void init_hmac_context(RecordProofInfo* rpi){
    const char *kLabelPrefix = "TLS 1.3, ";
    const unsigned int kLabelPrefixLen = strlen(kLabelPrefix);
	PRUint8* ptr;

	rpi->hmac = NULL;
	rpi->hmac_info_len = 2 + 1 + kLabelPrefixLen + strlen(SALT_TREE_LABEL) + 1;
	rpi->hmac_info = (PRUint8*) PORT_Alloc(rpi->hmac_info_len);
	ptr =  rpi->hmac_info;
	ptr = ssl_EncodeUintX(rpi->salt_size, 2, ptr);
	ptr = ssl_EncodeUintX(kLabelPrefixLen + strlen(SALT_TREE_LABEL), 1, ptr);
    PORT_Memcpy(ptr, kLabelPrefix, kLabelPrefixLen);
    ptr += kLabelPrefixLen;
    PORT_Memcpy(ptr, SALT_TREE_LABEL, strlen(SALT_TREE_LABEL));
    ptr += strlen(SALT_TREE_LABEL);
    ptr = ssl_EncodeUintX(0, 1, ptr);
    PORT_Assert((ptr - rpi->hmac_info) == rpi->hmac_info_len);
}

// Initialize the record information from information in the proof
static RecordProofInfo* init_proof_info_from_plaintext_proof(ProofPar* proofPar, PlaintextProofNode* proofNode, PRUint8* compressed_record, ProofMerkleNode* hash_locs, PRUint8** proof_merkle_hashes, ProofSalt* salt_locs){
	RecordProofInfo rpival = { .salt_size = proofPar->salt_size, .hash_size = proofPar->hash_size, .chunk_size = proofPar->chunk_size, .hash_type = proofPar->hash_type, .num_chunks = (PRUint32) ceil((double)proofNode->len_record/proofPar->chunk_size), .tree_levels = (PRUint32) ceil(log(rpival.num_chunks)/log(2)), .gen_orig = proofNode->gen_orig, .hkdf_mechanism = tls13_GetHkdfMechanismForHash(rpival.hash_type)};
	rpival.record_length = proofNode->len_record;
	rpival.salt_index = 0;
	rpival.chunk_index = 0;
	rpival.num_hashes = 0;	
	rpival.hash_locs = hash_locs;
	rpival.proof_merkle_hashes = proof_merkle_hashes;
	rpival.salt_locs = salt_locs;
	rpival.num_salts = 0;
	rpival.initialized_from_proof = PR_TRUE;
	rpival.ctx = PK11_CreateDigestContext(ssl3_HashTypeToOID(rpival.hash_type));

	// Copy, do this to allow const values
	RecordProofInfo* rpi = (RecordProofInfo*) PORT_Alloc(sizeof(RecordProofInfo));
	PORT_Memcpy(rpi, &rpival, sizeof(rpival));
	if(allocate_salts(rpi) != SECSuccess) return NULL;
	rpi->hidden_chunk_ids = NULL;
	rpi->num_hidden_chunks = 0;
	rpi->record = compressed_record;
	init_hmac_context(rpi);
	return rpi;
}

// Initialize the record information from information in the proof
static RecordProofInfo* init_proof_info_from_proof(ProofPar* proofPar, HiddenPlaintextProofNode* proofNode, PRUint8* compressed_record, ProofMerkleNode* hash_locs, PRUint8** proof_merkle_hashes, ProofSalt* salt_locs){
	RecordProofInfo rpival = { .salt_size = proofPar->salt_size, .hash_size = proofPar->hash_size, .chunk_size = proofPar->chunk_size, .hash_type = proofPar->hash_type, .num_chunks = (PRUint32) ceil((double)proofNode->len_record/proofPar->chunk_size), .tree_levels = (PRUint32) ceil(log(rpival.num_chunks)/log(2)), .gen_orig = proofNode->gen_orig, .hkdf_mechanism = tls13_GetHkdfMechanismForHash(rpival.hash_type)};
	rpival.record_length = proofNode->len_record;
	rpival.salt_index = 0;
	rpival.chunk_index = 0;
	rpival.num_hashes = proofNode->num_hashes;	
	rpival.hash_locs = hash_locs;
	rpival.proof_merkle_hashes = proof_merkle_hashes;
	rpival.salt_locs = salt_locs;
	rpival.num_salts = proofNode->num_salts;
	rpival.initialized_from_proof = PR_TRUE;
	rpival.ctx = PK11_CreateDigestContext(ssl3_HashTypeToOID(rpival.hash_type));

	// Copy, do this to allow const values
	RecordProofInfo* rpi = (RecordProofInfo*) PORT_Alloc(sizeof(RecordProofInfo));
	PORT_Memcpy(rpi, &rpival, sizeof(rpival));
	if(allocate_salts(rpi) != SECSuccess) return NULL;
	if(rpi->num_hashes > 0){
		if(compute_hidden_chunks_from_proof(rpi) != SECSuccess) return NULL;
	}else{
		rpi->hidden_chunk_ids = NULL;
		rpi->num_hidden_chunks = 0;
		rpi->record = compressed_record;
	}
	init_hmac_context(rpi);
	return rpi;
}

// Initialize the record information 
static RecordProofInfo* init_proof_info(sslSocket *ss, const PRUint8* record, PRUint16 record_length, PRBool received){
	RecordProofInfo rpival = { .hash_size = tls13_GetHashSize(ss), .salt_size = ss->xtnData.salt_size, .chunk_size = ss->xtnData.chunk_size, .hash_type = tls13_GetHash(ss), .num_chunks = (PRUint32) ceil((double)record_length/rpival.chunk_size), .tree_levels = (PRUint32) ceil(log(rpival.num_chunks)/log(2)), .gen_orig = received ^ ss->sec.isServer, .hkdf_mechanism = tls13_GetHkdfMechanismForHash(rpival.hash_type)};
	rpival.record = record;
	rpival.record_length = record_length;
	rpival.salt_index = 0;
	rpival.chunk_index = 0;
	rpival.num_hashes = 0;	
	rpival.hash_locs = NULL;
	rpival.proof_merkle_hashes = NULL;
	rpival.hidden_chunk_ids = NULL;
	rpival.num_hidden_chunks = 0;
	rpival.salt_locs = NULL;
	rpival.num_salts = 0;
	rpival.initialized_from_proof = PR_FALSE;
	rpival.ctx = PK11_CreateDigestContext(ssl3_HashTypeToOID(rpival.hash_type));

#ifdef TRACE
	SSL_TRC(50, ("[TLS-N] Num_chunks: %i\n", rpival.num_chunks));
#endif

	// Copy, do this to allow const values
	RecordProofInfo* rpi = (RecordProofInfo*) PORT_Alloc(sizeof(RecordProofInfo));
	PORT_Memcpy(rpi, &rpival, sizeof(rpival));
	if(allocate_salts(rpi) != SECSuccess) return NULL;
	init_hmac_context(rpi);
	return rpi;
}
	


static
SECStatus find_sensitive_chunks(RecordProofInfo *rpi){

    char *reg_str[] = {
        "[&\\?]passwd=([^&[:space:]]*)[&[:space:]]",
        "[&\\?]pass=([^&[:space:]]*)[&[:space:]]",
        "[&\\?]access_token=([^&[:space:]]*)[&[:space:]]",
        "Cookie:(.*)\n",
        "Authorization:(.*)\n",
        NULL
    };

	regex_t regex;
	PRInt16 reti;
	PRUint16 offset = 0;
	PRUint16* hidden_chunk_ids = NULL;
	// Number of hidden chunks
    PRUint16 num_hidden = 0;
    PRUint16 startchunk;
    PRUint16 stopchunk;
    int i;
	int reg_ex_id = 0;

    while(reg_str[reg_ex_id] != NULL) {
		// TODO: Compile this once
		// Compile regular expression 
        reti = regcomp(&regex, reg_str[reg_ex_id], REG_EXTENDED);

		if (reti) {
#ifdef TRACE
			ssl_Trace("[TLS-N] Error: Could not compile regex\n");
#endif
			exit(1);
		}
        size_t ngroups = regex.re_nsub + 1;
        regmatch_t *groups = (regmatch_t *) PORT_Alloc(ngroups * sizeof(regmatch_t));
        
        regmatch_t pmatch;
        offset = 0; 

		// Search for sensitive chunks
        while(offset < rpi->record_length){
            reti = regexec(&regex, (char*) rpi->record+offset, ngroups, groups, 0);
            if (!reti) {
				size_t g_idx;
                for (g_idx = 1; g_idx < ngroups; g_idx++){
                    pmatch = groups[g_idx];

                    startchunk = (offset+pmatch.rm_so)/rpi->chunk_size;
                    stopchunk = (offset+pmatch.rm_eo)/rpi->chunk_size;

					// Mark the hidden chunks
					for(i = startchunk; i <= stopchunk; ++i){
						// If already hidden
						if(!is_hidden_chunk(hidden_chunk_ids, num_hidden, i)){
							hidden_chunk_ids = (PRUint16*) PORT_Realloc(hidden_chunk_ids, (num_hidden + 1)* sizeof(PRUint16));
							// TODO: Sort we can do a fast lookup
							hidden_chunk_ids[num_hidden] = i;
							num_hidden++;
						}
					}
					// Adjust the offset so that we continue searching in the next chunk 
					offset += pmatch.rm_eo;
				}
			} else if(reti == REG_NOMATCH){
				break;
			} else {
	#ifdef TRACE
				char msgbuf[128];
				regerror(reti, &regex, msgbuf, sizeof(msgbuf));
				ssl_Trace("Regex match failed: %s\n", msgbuf);
	#endif
				return SECFailure;
			}
		}
		// Free memory allocated by regcomp
	    regfree(&regex);
		reg_ex_id++;
		PORT_Free(groups);

	}

    rpi->hidden_chunk_ids = hidden_chunk_ids;
    rpi->num_hidden_chunks = num_hidden;
    return SECSuccess;
}





static PRUint16
ceil_div8(PRUint16 num){
	PRUint16 res = num >> 3;
	if ((num & 7) != 0){
		res++;
	}
	return res;
}

/*
static SECStatus
tlsproof_hash_begin(sslSocket *ss, PK11Context ** out_ctx)
{
    PK11Context *ctx = NULL;

	ctx = PK11_CreateDigestContext(ssl3_HashTypeToOID(tls13_GetHash(ss)));
	if (!ctx) {
		ssl_MapLowLevelError(SSL_ERROR_SHA_DIGEST_FAILURE);
		return SECFailure;
	}

	if (PK11_DigestBegin(ctx) != SECSuccess) {
		ssl_MapLowLevelError(SSL_ERROR_SHA_DIGEST_FAILURE);
		PK11_DestroyContext(ctx, PR_TRUE);
	    return SECFailure;
	}
	*out_ctx = ctx;
    return SECSuccess;
}*/

static SECStatus
tlsproof_hash_begin2(PK11Context * ctx)
{

	if (PK11_DigestBegin(ctx) != SECSuccess) {
		ssl_MapLowLevelError(SSL_ERROR_SHA_DIGEST_FAILURE);
		PK11_DestroyContext(ctx, PR_TRUE);
	    return SECFailure;
	}
    return SECSuccess;
}

static SECStatus 
tlsproof_hash_zeroes(PK11Context *ctx, const PRUint32 inbuf_len){
	// No more padding
	return SECSuccess;
	PRUint8 buf[inbuf_len];
	bzero(buf, inbuf_len);

	if (PK11_DigestOp(ctx,
					  buf,
					  inbuf_len) != SECSuccess) {
		ssl_MapLowLevelError(SSL_ERROR_SHA_DIGEST_FAILURE);
		PK11_DestroyContext(ctx, PR_TRUE);
		return SECFailure;
	}
    return SECSuccess;
}

static SECStatus 
tlsproof_hash_op(PK11Context *ctx, const void* inbuf, const PRUint32 inbuf_len){
	if (PK11_DigestOp(ctx,
					  inbuf,
					  inbuf_len) != SECSuccess) {
		ssl_MapLowLevelError(SSL_ERROR_SHA_DIGEST_FAILURE);
		PK11_DestroyContext(ctx, PR_TRUE);
	    return SECFailure;
	}
    return SECSuccess;
}



// Hash in Network-Byte order
static SECStatus 
tlsproof_hash_op_nbo(PK11Context *ctx, const void* inbuf, const PRUint32 inbuf_len){
// TODO decide whether to do this or not
	return tlsproof_hash_op(ctx, inbuf, inbuf_len);

	PRUint16 tmp2;
	PRUint32 tmp4;
	if(inbuf_len == 2){
		tmp2 = htobe16(* (PRUint16*)inbuf);
		return tlsproof_hash_op(ctx, &tmp2, inbuf_len);
	}else if(inbuf_len == 4){
		tmp4 = htobe32(* (PRUint32*)inbuf);
		return tlsproof_hash_op(ctx, &tmp4, inbuf_len);
	}else{
		PORT_Assert(0);
		return SECFailure;
	}
}


/*
static SECStatus
tlsproof_hash_finish(sslSocket *ss, PK11Context *ctx, PRUint8* outbuf, unsigned int outbuf_len){
    unsigned int len;
    SECStatus rv;

    rv = PK11_DigestFinal(ctx, outbuf, &len, outbuf_len);
    if (rv != SECSuccess) {
        ssl_MapLowLevelError(SSL_ERROR_DIGEST_FAILURE);
	    PK11_DestroyContext(ctx, PR_TRUE);
	    return SECFailure;
    }
    PORT_Assert(len == tls13_GetHashSize(ss));
    PK11_DestroyContext(ctx, PR_TRUE);

    return SECSuccess;
}*/

static SECStatus
tlsproof_hash_finish2(PK11Context *ctx, PRUint8* outbuf, unsigned int outbuf_len){
    unsigned int len;
    SECStatus rv;

    rv = PK11_DigestFinal(ctx, outbuf, &len, outbuf_len);
    if (rv != SECSuccess) {
        ssl_MapLowLevelError(SSL_ERROR_DIGEST_FAILURE);
	    PK11_DestroyContext(ctx, PR_TRUE);
	    return SECFailure;
    }
    return SECSuccess;
}

/*When a message of content type tlsproof message is received it is tranfered to this
 *function. It will look at the sub-type and transfert it to the correct function*/
SECStatus
tlsproof_HandleMessage(sslSocket *ss, sslBuffer *origBuf)
{
	SECStatus rv;

	TLSProofMessageType proofMessageType;
	PRInt32 length;

	if(!ssl3_ExtensionNegotiated(ss,ssl_tls13_tls_proof_xtn))
		return SECFailure;

	length = origBuf->len;

	if(length <= 0) return SECFailure;

	//Get the sub-content type
	proofMessageType = origBuf->buf[0];

	//Call the corresponding function
	switch(proofMessageType){
	case tlsproof_message_type_request:

		rv = tlsproof_handleMessageRequest(ss,origBuf);
		if(rv != SECSuccess) return SECFailure;

		break;
	case tlsproof_message_type_response:

		rv = tlsproof_handleMessageResponse(ss, origBuf);
		if(rv != SECSuccess) return SECFailure;

		break;
	default:

		return SECFailure;
		break;

	}
	return SECSuccess;
}

/*Set *val to TRUE if the negotiation was succsessfull or set *val to FALSE if
 * the negotiation failed*/
SECStatus SSL_TLSProofIsNegociated(PRFileDesc *fd, PRBool *val)
{
	*val = PR_FALSE;
	sslSocket *ss = ssl_FindSocket(fd);

	if (!ss) {
	        SSL_DBG(("%d: SSL[%d]: bad socket in SSL_TLSProofIsNegociated",
	                 SSL_GETPID(), fd));
	        return SECFailure;
	}

	if(ssl3_ExtensionNegotiated(ss,ssl_tls13_tls_proof_xtn))
		*val = PR_TRUE;

	return SECSuccess;
}

/*Call by a client to send the proof request*/
SECStatus SSL_TLSProofRequestProof(PRFileDesc *fd)
{

	SECStatus rv = SECFailure;
	sslSocket *ss = ssl_FindSocket(fd);
	PRInt32 sent = -1;
	PRInt32 rqLength = TLS_PROOF_MESSAGE_TYPE_SIZE;
	TLSProofMessageType request = tlsproof_message_type_request;

	//Hold lock to send messages
	ssl_GetSSL3HandshakeLock(ss);
	ssl_GetXmitBufLock(ss);

	if(!ssl3_ExtensionNegotiated(ss,ssl_tls13_tls_proof_xtn))
		return SECFailure;

	//Send the proof request
	sent = ssl3_SendRecord(ss, NULL, content_tls_proof_message, (PRUint8 *) &request, rqLength, 0);

	if(sent > 0) rv = SECSuccess;

	SSL_TRC(15, ("Proof request sent."));

	ssl_ReleaseXmitBufLock(ss);
	ssl_ReleaseSSL3HandshakeLock(ss);

	return rv;
}


// TODO: const and int
static PRInt32	salt_is_in_proof(ProofSalt* salt_locs, PRUint16 num_proof_salts, int level, PRUint16 salt_index){
    int i;
    for(i = 0; i < num_proof_salts; ++i){
        if(salt_locs[i].tree_level == level && salt_locs[i].salt_index == salt_index){
            return i;
        }
    }
    return -1;	
}


SECStatus my_hkdf_expand(RecordProofInfo* rpi, PRUint8* outbuf, PRUint8* inbuf){
                /* T(1) = HMAC-Hash(prk, "" | info | 0x01)
                 * T(n) = HMAC-Hash(prk, T(n-1) | info | n
                 * key material = T(1) | ... | T(n)
                 */
                CK_BYTE i;
                unsigned iterations = PR_ROUNDUP(2 * rpi->salt_size, rpi->hash_size) / rpi->hash_size;
				if(rpi->hmac == NULL){
	                rpi->hmac = HMAC_Create(HASH_GetHashObject(rpi->hash_type), inbuf, rpi->salt_size, 0);
				}else{
					HMAC_Init(rpi->hmac, HASH_GetHashObject(rpi->hash_type), inbuf, rpi->salt_size, 0);
				}
                for (i = 1; i <= iterations; ++i) {
                    unsigned len;
                    HMAC_Begin(rpi->hmac);
                    if (i > 1) {
                        HMAC_Update(rpi->hmac, outbuf + ((i - 2) * rpi->hash_size), rpi->hash_size);
                    }
                    HMAC_Update(rpi->hmac, rpi->hmac_info, rpi->hmac_info_len);
                    HMAC_Update(rpi->hmac, &i, 1);
                    HMAC_Finish(rpi->hmac, outbuf + ((i - 1) * rpi->hash_size), &len, rpi->hash_size);
                    PORT_Assert(len == rpi->hash_size);
                }
	return SECSuccess;
}


//SECStatus compute_salt_tree2(RecordProofInfo* rpi, const int level, PK11SymKey* int_salt_secret){
SECStatus compute_salt_tree2(RecordProofInfo* rpi, const int level, PRUint8* int_salt_secret){
	PRUint8 new_salt[2 * rpi->salt_size];
//	PK11SymKey* left;
//	PK11SymKey* right;
	PRUint8* left;
	PRUint8* right;

	if(rpi->salt_index >= rpi->num_chunks){
		return SECSuccess;
	}

	// Special case: single chunk
	if(rpi->num_chunks == 1){
		PORT_Memcpy(rpi->salts[rpi->salt_index], int_salt_secret, rpi->salt_size);
		rpi->salt_index += 1;
		return SECSuccess;
	}


	my_hkdf_expand(rpi, new_salt, int_salt_secret);

//	if(tls13_HkdfExpandLabelRaw(int_salt_secret, rpi->hash_type, NULL, 0, rpi->salt_tree_label, rpi->salt_tree_label_len, new_salt, 2 * rpi->salt_size) != SECSuccess) return SECFailure;
//	if(tlsproof_hash_begin2(rpi->ctx) != SECSuccess) return SECFailure;
//	if(tlsproof_hash_op(rpi->ctx, int_salt_secret, rpi->salt_size) != SECSuccess) return SECFailure;
//	if(tlsproof_hash_finish2(rpi->ctx, new_salt, sizeof(new_salt)) != SECSuccess) return SECFailure;
	
	// Split into left and right
//	left = create_sym_key_for_salt(rpi, new_salt);
//	right = create_sym_key_for_salt(rpi, new_salt + rpi->salt_size); 
	left = new_salt;
	right = new_salt + rpi->salt_size;

	// Leaf Detection: A leaf is on the last level or is within the last two indices

	// Left side

	// Check if leaf
	if(level == rpi->tree_levels - 1){
		// Save salt values if bottom is reached
		PORT_Memcpy(rpi->salts[rpi->salt_index], left, rpi->salt_size);
		rpi->salt_index += 1;
	} else {
		// Go to lower level
		if(compute_salt_tree2(rpi, level+1, left) != SECSuccess) return SECFailure;
	}

	if(rpi->salt_index >= rpi->num_chunks){
		return SECSuccess;
	}

	// Right side

	// Check if leaf
	if(level == rpi->tree_levels - 1){
		PORT_Assert(rpi->salt_index < rpi->num_chunks);
		PORT_Memcpy(rpi->salts[rpi->salt_index], right, rpi->salt_size);
		rpi->salt_index += 1;
	} else {
		if(compute_salt_tree2(rpi, level+1, right) != SECSuccess) return SECFailure;
	}
//	PK11_FreeSymKey(left);
//	PK11_FreeSymKey(right);
	return SECSuccess;
}

// int_salt_secret has salt_size
// salt_index is the next free index
SECStatus compute_salt_tree(RecordProofInfo* rpi, PRUint8* int_salt_secret){
	rpi->salt_index = 0;
//	PK11SymKey* int_salt_key = create_sym_key_for_salt(rpi, int_salt_secret);
//	SECStatus rv = compute_salt_tree2(rpi, 0, int_salt_key);
	SECStatus rv = compute_salt_tree2(rpi, 0, int_salt_secret);
	PORT_Assert(rpi->num_chunks == rpi->salt_index);
//	PK11_FreeSymKey(int_salt_key);
	return rv;
}

SECStatus compute_salts_from_proof_salts2(RecordProofInfo* rpi, const int level, PRUint8** proof_salts){

	PRInt32 in_proof_index;

	if(rpi->salt_index >= rpi->num_chunks){
		return SECSuccess;
	}

	// Special case: single chunk
	if(rpi->num_chunks == 1){
		// Handle this differently
		PORT_Assert(PR_FALSE);
	}

	// If this part is in the proof
	in_proof_index = salt_is_in_proof(rpi->salt_locs, rpi->num_salts, level, rpi->salt_index);
	if(in_proof_index != -1){
		// Just copy it, if it is a final salt
		if(level == rpi->tree_levels){
			PORT_Memcpy(rpi->salts[rpi->salt_index], proof_salts[in_proof_index], rpi->salt_size);
			rpi->salt_index += 1;
			return SECSuccess;
		} else {
			// Take it from the proof and run the normal subtree execution
			return compute_salt_tree2(rpi, level, proof_salts[in_proof_index]);
		}
	}

	// Useless leaf
    if(level == rpi->tree_levels){
		rpi->salt_index += 1;
		return SECSuccess;
	}

	// Traverse down
	if(compute_salts_from_proof_salts2(rpi, level+1, proof_salts) != SECSuccess) return SECFailure;
	if(rpi->salt_index >= rpi->num_chunks){
		return SECSuccess;
	}
	if(compute_salts_from_proof_salts2(rpi, level+1, proof_salts) != SECSuccess) return SECFailure;


	return SECSuccess;
}

SECStatus compute_salts_from_proof_salts(RecordProofInfo* rpi, PRUint8** proof_salts){
	rpi->salt_index = 0;
	return compute_salts_from_proof_salts2(rpi, 0, proof_salts);
}

SECStatus compute_proof_salts2(RecordProofInfo* rpi, const int level, PRUint8* int_salt_secret, PRBool* nonsensitive_subtree, ProofSalt* nonsense_loc, PRUint8* hash_for_nonsense){
	PRUint8 new_salt[rpi->hash_size];
	PRUint8* left;
	PRUint8* right;
	PRBool left_nonsensitive;
	PRBool right_nonsensitive;
	ProofSalt left_loc;
	ProofSalt right_loc;
	PRUint8 left_hash_for_nonsense[rpi->hash_size];
	PRUint8 right_hash_for_nonsense[rpi->hash_size];
	PRUint16 orig_salt_index = rpi->salt_index;

	if(rpi->salt_index >= rpi->num_chunks){
		return SECSuccess;
	}

	// Special case: single chunk
	if(rpi->num_chunks == 1){
		// These cases should be handled separately
		PORT_Assert(PR_FALSE);
	}

	my_hkdf_expand(rpi, new_salt, int_salt_secret);

    // Split into left and right
	left = new_salt;
	right = new_salt + rpi->salt_size; 

	// Leaf Detection: A leaf is on the last level or is within the last two indices


	// Check if lowest level
	if(level == rpi->tree_levels - 1){
		left_nonsensitive = ! is_hidden_chunk(rpi->hidden_chunk_ids, rpi->num_hidden_chunks, rpi->salt_index);
		right_nonsensitive = (rpi->salt_index+1 < rpi->num_chunks) && !is_hidden_chunk(rpi->hidden_chunk_ids, rpi->num_hidden_chunks, rpi->salt_index+1);

		// If both are not hidden, push it up
		if(left_nonsensitive && right_nonsensitive){
			*nonsensitive_subtree = PR_TRUE;
			nonsense_loc->tree_level = level;
			nonsense_loc->salt_index = rpi->salt_index;
			PORT_Memcpy(hash_for_nonsense, int_salt_secret, rpi->hash_size);
			rpi->salt_index += 2;
			return SECSuccess;
		}
		*nonsensitive_subtree = PR_FALSE;
		if(left_nonsensitive){
			rpi->salt_locs[rpi->num_salts].tree_level = level + 1;
			rpi->salt_locs[rpi->num_salts].salt_index = rpi->salt_index;
			PORT_Memcpy(rpi->salts[rpi->num_salts], left, rpi->salt_size);
			rpi->num_salts++;
		}
		rpi->salt_index += 1;
		if(rpi->salt_index >= rpi->num_chunks){
			*nonsensitive_subtree = left_nonsensitive;
			return SECSuccess;
		}
		if(right_nonsensitive){
			rpi->salt_locs[rpi->num_salts].tree_level = level + 1;
			rpi->salt_locs[rpi->num_salts].salt_index = rpi->salt_index;
			PORT_Memcpy(rpi->salts[rpi->num_salts], right, rpi->salt_size);
			rpi->num_salts++;
		}
		rpi->salt_index += 1;		
		PORT_Assert(rpi->salt_index <= rpi->num_chunks);


	} else {
		// Go to lower level
		if(compute_proof_salts2(rpi, level+1, left, &left_nonsensitive, &left_loc, left_hash_for_nonsense) != SECSuccess) return SECFailure;

		if(rpi->salt_index >= rpi->num_chunks){
			if (left_nonsensitive){
				// If only left is around, push it up
				*nonsensitive_subtree = PR_TRUE;
				nonsense_loc->tree_level = left_loc.tree_level;
				nonsense_loc->salt_index = left_loc.salt_index;
                PORT_Memcpy(hash_for_nonsense, left_hash_for_nonsense, rpi->hash_size);
			} else {
				*nonsensitive_subtree = PR_FALSE;
			}
			return SECSuccess;
		}

		if(compute_proof_salts2(rpi, level+1, right, &right_nonsensitive, &right_loc, right_hash_for_nonsense) != SECSuccess) return SECFailure;

		// Merge the two sides
		if(left_nonsensitive && right_nonsensitive){
			// Both hidden
			*nonsensitive_subtree = PR_TRUE;
			nonsense_loc->tree_level = level;
			nonsense_loc->salt_index = orig_salt_index;
			PORT_Memcpy(hash_for_nonsense, int_salt_secret, rpi->hash_size);
		} else {
			*nonsensitive_subtree = PR_FALSE;
			if (left_nonsensitive){
				PORT_Memcpy(rpi->salts[rpi->num_salts], left_hash_for_nonsense, rpi->salt_size);
				PORT_Memcpy(&(rpi->salt_locs[rpi->num_salts]), &left_loc, sizeof(ProofSalt));
				rpi->num_salts++;
			} else if (right_nonsensitive){
				PORT_Memcpy(rpi->salts[rpi->num_salts], right_hash_for_nonsense, rpi->salt_size);
				PORT_Memcpy(&(rpi->salt_locs[rpi->num_salts]), &right_loc, sizeof(ProofSalt));
				rpi->num_salts++;
			}
		}
	}

	return SECSuccess;
}

SECStatus compute_proof_salts(RecordProofInfo* rpi, PRUint8* int_salt_secret){
	PRBool sensitive_subtree;
	rpi->num_salts = 0;
	rpi->salt_index = 0;
	if(rpi->salt_locs == NULL){
		rpi->salt_locs = (ProofSalt*) PORT_Alloc((rpi->num_chunks - rpi->num_hidden_chunks)* sizeof(ProofSalt));
	}
	return compute_proof_salts2(rpi, 0, int_salt_secret, &sensitive_subtree, NULL, NULL);
	// TODO: Assertion
}


// outbuf has to be of length hash_size 
static SECStatus compute_proof_merkle_hashes2(RecordProofInfo* rpi, int level, PRUint8* outbuf, PRBool *am_hidden, ProofMerkleNode* hidden_loc){
	PRUint8 left_child[rpi->hash_size];
	PRUint8 right_child[rpi->hash_size];
	PRBool left_hidden;
	PRBool right_hidden;
	ProofMerkleNode left_loc;
	ProofMerkleNode right_loc;
	PRUint16 orig_chunk_index = rpi->chunk_index;

	if(rpi->chunk_index >= rpi->num_chunks){
		*am_hidden = PR_FALSE;
		return SECSuccess;
	}

	// Check if this a leaf
	if(level == rpi->tree_levels){
		if(is_hidden_chunk(rpi->hidden_chunk_ids, rpi->num_hidden_chunks, rpi->chunk_index)){
		
			PRUint16 chunk_length = get_chunk_length(rpi);
			// Compute hash from salt and chunk
			if(tlsproof_hash_begin2(rpi->ctx) != SECSuccess) return SECFailure;
			if(tlsproof_hash_op(rpi->ctx, rpi->salts[rpi->chunk_index], rpi->salt_size) != SECSuccess) return SECFailure;
			if(tlsproof_hash_op(rpi->ctx, &(rpi->record[rpi->chunk_size * rpi->chunk_index]), chunk_length) != SECSuccess) return SECFailure;
			if(chunk_length < rpi->chunk_size){
				// Pad last chunk with zeros
				if(tlsproof_hash_zeroes(rpi->ctx, rpi->chunk_size - chunk_length) != SECSuccess) return SECFailure;	
			}

			// Special case: Root node
			if(level == 0){
				// This should never happen. A completely hidden node should be a merkle_hash_node
				PORT_Assert(0);
				return SECFailure;
			}
			if(tlsproof_hash_finish2(rpi->ctx, outbuf, rpi->hash_size) != SECSuccess) return SECFailure;


			*am_hidden = PR_TRUE;	
			hidden_loc->tree_level = level;
			hidden_loc->chunk_index = rpi->chunk_index;
		} else {
			*am_hidden = PR_FALSE;
		}
		rpi->chunk_index += 1;
		return SECSuccess;
	} else {
		// left, right, length, client_orig 
		if(compute_proof_merkle_hashes2(rpi, level + 1, left_child, &left_hidden, &left_loc) != SECSuccess) return SECFailure;

		// If we don't need the right side any more, just push the left side upwards
		if(rpi->chunk_index >= rpi->num_chunks){
			*am_hidden = left_hidden;
			if(left_hidden){
				PORT_Memcpy(outbuf, left_child, rpi->hash_size);	
				hidden_loc->tree_level = left_loc.tree_level;
				hidden_loc->chunk_index = left_loc.chunk_index;
			}
			return SECSuccess;
		}

		if(compute_proof_merkle_hashes2(rpi, level + 1, right_child, &right_hidden, &right_loc) != SECSuccess) return SECFailure;
		// Compute hash
		*am_hidden = right_hidden && left_hidden;
		if(*am_hidden){
			if(tlsproof_hash_begin2(rpi->ctx) != SECSuccess) return SECFailure;
			if(tlsproof_hash_op(rpi->ctx, left_child, rpi->hash_size) != SECSuccess) return SECFailure;
			if(tlsproof_hash_op(rpi->ctx, right_child, rpi->hash_size) != SECSuccess) return SECFailure;
			// Special case: Root node
			if(level == 0){
				// This should never happen. A completely hidden node should be a merkle_hash_node
				PORT_Assert(0);
				return SECFailure;
			}
			if(tlsproof_hash_finish2(rpi->ctx, outbuf, rpi->hash_size) != SECSuccess) return SECFailure;
			hidden_loc->tree_level = level;
			hidden_loc->chunk_index = orig_chunk_index;
		} else if (left_hidden) {
			rpi->hash_locs[rpi->num_hashes].tree_level = left_loc.tree_level;
			rpi->hash_locs[rpi->num_hashes].chunk_index = left_loc.chunk_index;
			PORT_Memcpy(rpi->proof_merkle_hashes[rpi->num_hashes], left_child, rpi->hash_size);
			rpi->num_hashes += 1;
		} else if (right_hidden) {
			rpi->hash_locs[rpi->num_hashes].tree_level = right_loc.tree_level;
			rpi->hash_locs[rpi->num_hashes].chunk_index = right_loc.chunk_index;
			PORT_Memcpy(rpi->proof_merkle_hashes[rpi->num_hashes], right_child, rpi->hash_size);
			rpi->num_hashes += 1;
		}
		return SECSuccess;		
	}
}

SECStatus compute_proof_merkle_hashes(RecordProofInfo* rpi){
	if(rpi->hash_locs == NULL){
		rpi->hash_locs = (ProofMerkleNode*) PORT_Alloc(rpi->num_hidden_chunks * sizeof(ProofMerkleNode));
		if(rpi->hash_locs == NULL) return SECFailure;
	}
	if(rpi->proof_merkle_hashes == NULL){
		rpi->proof_merkle_hashes = allocate_string_array(rpi->hash_size, rpi->num_hidden_chunks); 
		if(rpi->proof_merkle_hashes == NULL) return SECFailure;
	}
	rpi->num_hashes = 0;
	rpi->chunk_index = 0;
		
	PRBool am_hidden;
	if(compute_proof_merkle_hashes2(rpi, 0, NULL, &am_hidden, NULL) != SECSuccess) return SECFailure;
	PORT_Assert(rpi->chunk_index == rpi->num_chunks);
	PORT_Assert(!am_hidden);
	return SECSuccess;
}

// TODO: const and int
static PRInt32 hash_is_in_proof(ProofMerkleNode* hash_locs, PRUint16 num_hashes, int level, PRUint16 chunk_index){
    int i;
    for(i = 0; i < num_hashes; ++i){
        if(hash_locs[i].tree_level == level && hash_locs[i].chunk_index == chunk_index){
            return i;
        }
    }
    return -1;	
}



// outbuf has to be of length hash_size 
SECStatus compute_merkle_tree2(RecordProofInfo* rpi, int level, PRUint8* outbuf){
	PRUint8 left_child[rpi->hash_size];
	PRUint8 right_child[rpi->hash_size];
	PRUint16 chunk_length;

	if(rpi->chunk_index >= rpi->num_chunks){
		return SECSuccess;
	}

	// Use existing hashes when generating from proof
	if(rpi->num_hashes != 0){
		PRInt32 in_proof_index = hash_is_in_proof(rpi->hash_locs, rpi->num_hashes, level, rpi->chunk_index);
		// Found a hash in the proof
		if(in_proof_index != -1){
			PORT_Memcpy(outbuf, rpi->proof_merkle_hashes[in_proof_index], rpi->hash_size);
			// Add the leaves we skipped
			rpi->chunk_index += num_skipped_leaves(rpi, level, rpi->chunk_index);
			return SECSuccess;
		}
	}


	chunk_length = get_chunk_length(rpi);

	// Check if this a leaf
	if(level == rpi->tree_levels){
	
		// Compute hash from salt and chunk
		if(tlsproof_hash_begin2(rpi->ctx) != SECSuccess) return SECFailure;
		if(tlsproof_hash_op(rpi->ctx, rpi->salts[rpi->chunk_index], rpi->salt_size) != SECSuccess) return SECFailure;
		if(tlsproof_hash_op(rpi->ctx, &(rpi->record[rpi->chunk_size * rpi->chunk_index]), chunk_length) != SECSuccess) return SECFailure;
		if(chunk_length < rpi->chunk_size){
			// Pad last chunk with zeros
			if(tlsproof_hash_zeroes(rpi->ctx, rpi->chunk_size - chunk_length) != SECSuccess) return SECFailure;	
		}
		// Special case: Root node
		if(level == 0){
			if(tlsproof_hash_op(rpi->ctx, (unsigned char*) &merkle_root_marker, sizeof(merkle_root_marker)) != SECSuccess) return SECFailure;
			if(tlsproof_hash_op_nbo(rpi->ctx, (unsigned char*) &(rpi->record_length), sizeof(rpi->record_length)) != SECSuccess) return SECFailure;
			if(tlsproof_hash_op(rpi->ctx, (unsigned char*) &(rpi->gen_orig), sizeof(rpi->gen_orig)) != SECSuccess) return SECFailure;
		}
		if(tlsproof_hash_finish2(rpi->ctx, outbuf, rpi->hash_size) != SECSuccess) return SECFailure;
		rpi->chunk_index += 1;
		return SECSuccess;
	} else {
		// left, right, length, gen_orig
		if(compute_merkle_tree2(rpi, level + 1, left_child) != SECSuccess) return SECFailure;

		// If we don't need the right side any more, just push the left side upwards
		if(rpi->chunk_index >= rpi->num_chunks){
			PORT_Memcpy(outbuf, left_child, rpi->hash_size);	
			return SECSuccess;
		}

		if(compute_merkle_tree2(rpi, level + 1, right_child) != SECSuccess) return SECFailure;
		// Compute hash
		if(tlsproof_hash_begin2(rpi->ctx) != SECSuccess) return SECFailure;
		if(tlsproof_hash_op(rpi->ctx, left_child, rpi->hash_size) != SECSuccess) return SECFailure;
		if(tlsproof_hash_op(rpi->ctx, right_child, rpi->hash_size) != SECSuccess) return SECFailure;
		// Special case: Root node
		if(level == 0){
			if(tlsproof_hash_op(rpi->ctx, (unsigned char*) &merkle_root_marker, sizeof(merkle_root_marker)) != SECSuccess) return SECFailure;
			if(tlsproof_hash_op_nbo(rpi->ctx, (unsigned char*) &(rpi->record_length), sizeof(rpi->record_length)) != SECSuccess) return SECFailure;
			if(tlsproof_hash_op(rpi->ctx, (unsigned char*) &(rpi->gen_orig), sizeof(rpi->gen_orig)) != SECSuccess) return SECFailure;
		}
		if(tlsproof_hash_finish2(rpi->ctx, outbuf, rpi->hash_size) != SECSuccess) return SECFailure;
		return SECSuccess;		
	}
}


// outbuf has to be of length hash_size 
SECStatus compute_merkle_tree(RecordProofInfo* rpi, PRUint8* outbuf){
	rpi->chunk_index = 0;
	rpi->num_hashes = 0;
	return compute_merkle_tree2(rpi, 0, outbuf);
}

// outbuf has to be of length hash_size 
SECStatus compute_merkle_tree_from_proof(RecordProofInfo* rpi, PRUint8* outbuf){
	rpi->chunk_index = 0;
	return compute_merkle_tree2(rpi, 0, outbuf);
}

static SECStatus sendEvidence(sslSocket *ss){
#ifdef EV_MEASURE_COMP
	PRTime measure_start = PR_Now();
#endif

	PRUint16 offset = 0;
	const PRUint32 hash_size = tls13_GetHashSize(ss);
	PRTime timeStampStop;
	SSLHashType hash_type =  tls13_GetHash(ss);
	PRUint16 chunk_size = ss->xtnData.chunk_size;
	PRUint16 salt_size = ss->xtnData.salt_size;

	if(ss->tlsproofMerkleRoot == NULL){
		return SECFailure;
	}
	
	timeStampStop = PR_Now();


	// Retrieve private key
	SECKEYPrivateKey *key = ss->sec.serverCert->serverKeyPair->privKey;

	// TODO: Hash other stuff
	// Hash to be signed: Signature, Timestamp, Timestamp
	SECItem data;
	data.type = siBuffer;
	data.len = hash_size;
	data.data = (unsigned char *) PORT_Alloc(data.len);

	PK11Context *ctx = PK11_CreateDigestContext(ssl3_HashTypeToOID(tls13_GetHash(ss)));
	if(tlsproof_hash_begin2(ctx) != SECSuccess) return SECFailure;
	if(tlsproof_hash_op(ctx, ss->tlsproofMerkleRoot, hash_size) != SECSuccess) return SECFailure;
	if(tlsproof_hash_op(ctx, &ss->tlsproofTimeStampStart, sizeof(ss->tlsproofTimeStampStart)) != SECSuccess) return SECFailure;
	if(tlsproof_hash_op(ctx, &timeStampStop, sizeof(timeStampStop)) != SECSuccess) return SECFailure;
	if(tlsproof_hash_op(ctx, &salt_size, sizeof(salt_size)) != SECSuccess) return SECFailure;
	if(tlsproof_hash_op(ctx, &chunk_size, sizeof(chunk_size)) != SECSuccess) return SECFailure;
	if(tlsproof_hash_op(ctx, &hash_type, sizeof(SSLHashType)) != SECSuccess) return SECFailure;
	if(tlsproof_hash_finish2(ctx, data.data, hash_size) != SECSuccess) return SECFailure;
	PK11_DestroyContext(ctx, PR_TRUE);

	// Where the signature will be stored
	SECItem signature;
	signature.type = siBuffer;
	signature.len = (unsigned int) PK11_SignatureLen(key);
	signature.data = (unsigned char *) PORT_Alloc(signature.len);

	// TODO: Hash

	// Sign
	PK11_Sign(key, &signature, &data);

#ifdef TRACE
	if (ssl_trace >= 25) {
		ssl_PrintBuf(ss, "[TLS-N] Signature: ", signature.data, signature.len);
	}
#endif

	 // Send the proof response
	ssl_GetSSL3HandshakeLock(ss);
	ssl_GetXmitBufLock(ss);

	PRInt32 respLength = TLS_PROOF_MESSAGE_TYPE_SIZE + EVIDENCE_MESSAGE_SIZE + signature.len + ceil_div8(ss->tlsproofOrderingVectorLen);
	unsigned char *response = PORT_Alloc(respLength);
	PRInt32 sent;

	TLSProofMessageType message_type = tlsproof_message_type_response;
	EvidenceMessage evMsg;
	// Timestamps
	evMsg.timeStampStart = ss->tlsproofTimeStampStart;
	evMsg.timeStampStop = timeStampStop;
	// Length of Signature
	evMsg.sig_len = signature.len;
	// Length of ordering vector
	evMsg.orderingVectorLen = ss->tlsproofOrderingVectorLen;

	offset = 0;

	WRITE_LEN_AT_OFFSET(response, offset, &message_type, TLS_PROOF_MESSAGE_TYPE_SIZE);

	// Add Struct
	WRITE_LEN_AT_OFFSET(response, offset, &evMsg, EVIDENCE_MESSAGE_SIZE);

	// Add Signature
	PORT_Memcpy(response+offset, signature.data, signature.len);
	offset += signature.len;

	// Add Ordering Vector 
	PORT_Memcpy(response+offset, ss->tlsproofOrderingVector, ceil_div8(ss->tlsproofOrderingVectorLen));
	offset += ceil_div8(ss->tlsproofOrderingVectorLen);

	PORT_Assert(offset == respLength);
	
#ifdef EV_MEASURE_COMP
	PRTime measure_stop = PR_Now();
	printf("[Measure-Evidence] %lu, %u, %u, %u, %u\n", measure_stop - measure_start, signature.len, data.len, respLength, ss->tlsproofOrderingVectorLen);
#endif

	// Send the response
	sent = ssl3_SendRecord(ss, NULL, content_tls_proof_message, response, respLength, 0);
	if(sent <= 0) return SECFailure;

	ssl_ReleaseXmitBufLock(ss);
	ssl_ReleaseSSL3HandshakeLock(ss);
	PORT_Free(response);
	PORT_Free(signature.data);
	PORT_Free(data.data);
	ss->tlsproofSentEvidence = 1;
	return SECSuccess;

}


SECStatus tlsproof_sendEvidenceOnClose(sslSocket *ss){
	if(ssl3_ExtensionNegotiated(ss,ssl_tls13_tls_proof_xtn) && ss->tlsproofOrderingVectorLen > 0 && ss->tlsproofSentEvidence != 1){
		return sendEvidence(ss);
	}
	return SECSuccess;
}


/*Function called when a proof request is sent. It generate the signature and send the proof response*/
static SECStatus tlsproof_handleMessageRequest(sslSocket *ss, sslBuffer  *origBuf)
{
	PRInt32 length;
	length = origBuf->len;

	if(!ssl3_ExtensionNegotiated(ss,ssl_tls13_tls_proof_xtn)){
#ifdef TRACE
	if (ssl_trace >= 25) {
		ssl_Trace("Received a proof request, but extension was not negotiated!");
	}
#endif
			return SECFailure;
	}

	if(length != 1){
#ifdef TRACE
	if (ssl_trace >= 25) {
		ssl_Trace("Received a proof request, but it was not correctly formatted!");
	}
#endif
				return SECFailure;
	}


	//Flush the buffer because it is not destined to application layer
	origBuf->len = 0;

#ifdef TRACE
	if (ssl_trace >= 25) {
		ssl_PrintBuf(ss, "Received a proof request! Generating a signature over the root hash:", ss->tlsproofMerkleRoot, tls13_GetHashSize(ss));
	}
#endif

	return sendEvidence(ss);

}


// No more padding
static PRUint32 recordPaddingSize(PRUint16 len_record, PRUint16 chunk_size){
	return 0;	
}

/*
static PRUint32 recordPaddingSize(PRUint16 len_record, PRUint16 chunk_size){
	PRUint32 padded_size = 0;
	PRUint32 remaining = len_record % chunk_size;
	if(remaining > 0){
		padded_size += chunk_size - remaining;
	}
	return padded_size;	
}*/

static SECStatus addPlaintextProofNode(unsigned char** proof_str_ptr, PRUint32* proof_offset_ptr, PRUint32* proof_size_ptr, TLSProofClientRecording* recording, PRBool received, PRUint16 salt_size, PRUint16 chunk_size){

	PRUint32 proof_offset = *proof_offset_ptr;
	PRUint32 record_padding_size = recordPaddingSize(recording->plaintext_size, chunk_size);
	
	// Add another proof node
	ProofNode proofNode;
	proofNode.node_type = plaintext_node;	

	PlaintextProofNode plaintextNode;
	plaintextNode.gen_orig = received;
	plaintextNode.len_record = recording->plaintext_size;
	
	unsigned char* proof_str = *proof_str_ptr;
	*proof_size_ptr += PROOF_NODE_SIZE + PLAINTEXT_PROOF_NODE_SIZE + recording->plaintext_size + record_padding_size + salt_size;
	proof_str = (unsigned char*) PORT_Realloc(proof_str, *proof_size_ptr);
	WRITE_LEN_AT_OFFSET(proof_str, proof_offset, &proofNode, PROOF_NODE_SIZE);
	WRITE_LEN_AT_OFFSET(proof_str, proof_offset, &plaintextNode, PLAINTEXT_PROOF_NODE_SIZE);
	WRITE_LEN_AT_OFFSET(proof_str, proof_offset, recording->plaintext, recording->plaintext_size);
	WRITE_ZEROES_AT_OFFSET(proof_str, proof_offset, record_padding_size);
	WRITE_LEN_AT_OFFSET(proof_str, proof_offset, recording->salt_secret, salt_size);
	PORT_Assert(proof_offset == *proof_size_ptr);
	*proof_str_ptr = proof_str;
	*proof_offset_ptr = proof_offset;
	return SECSuccess;
}

static SECStatus addHashChainNode(unsigned char** proof_str_ptr, PRUint32* proof_offset_ptr, PRUint32* proof_size_ptr, PRUint8* hash_chain, PRUint16 hash_size){
	PRUint32 proof_offset = *proof_offset_ptr;

	// Hash chain value
	// Add another proof node
	ProofNode proofNode;
	proofNode.node_type = hash_chain_node;	
	
    unsigned char* proof_str = *proof_str_ptr;
		
	*proof_size_ptr += sizeof(ProofNode) + hash_size;
	proof_str = (unsigned char*) PORT_Realloc(proof_str, *proof_size_ptr);
    WRITE_LEN_AT_OFFSET(proof_str, proof_offset, &proofNode, PROOF_NODE_SIZE);
	WRITE_LEN_AT_OFFSET(proof_str, proof_offset, hash_chain, hash_size);
	PORT_Assert(proof_offset == *proof_size_ptr);			
    *proof_str_ptr = proof_str;
	*proof_offset_ptr = proof_offset;
	return SECSuccess;
}


static SECStatus addMerkleProofNode(unsigned char** proof_str_ptr, PRUint32* proof_offset_ptr, PRUint32* proof_size_ptr, PRUint8* hash, PRUint16 hash_size){
	PRUint32 proof_offset = *proof_offset_ptr;

	// Add another proof node
	ProofNode proofNode;
	proofNode.node_type = merkle_hash_node;	

    unsigned char* proof_str = *proof_str_ptr;
		
	*proof_size_ptr += PROOF_NODE_SIZE + hash_size;
	proof_str = (unsigned char*) PORT_Realloc(proof_str, *proof_size_ptr);
    WRITE_LEN_AT_OFFSET(proof_str, proof_offset, &proofNode, PROOF_NODE_SIZE);
	WRITE_LEN_AT_OFFSET(proof_str, proof_offset, hash, hash_size);
	PORT_Assert(proof_offset == *proof_size_ptr);
    *proof_str_ptr = proof_str;
	*proof_offset_ptr = proof_offset;
	return SECSuccess;
}


PRUint8* advance_hash_chain2(PRUint8* hash_chain, PRUint8* hash, PRUint16 hash_size, SSLHashType hash_type){
	
	PK11Context *ctx = PK11_CreateDigestContext(ssl3_HashTypeToOID(hash_type));
	// Advance hash chain
	if(tlsproof_hash_begin2(ctx) != SECSuccess) return NULL;
    if(tlsproof_hash_op(ctx, &hash_chain_marker, sizeof(PRUint8)) != SECSuccess) return NULL;
    if(hash_chain != NULL){
		if(tlsproof_hash_op(ctx, hash_chain, hash_size) != SECSuccess) return NULL;
	}else{
		// Allocate space if necessary
		hash_chain = (PRUint8*) PORT_Alloc(hash_size);
	}
	if(tlsproof_hash_op(ctx, hash, hash_size) != SECSuccess) return NULL;
	if(tlsproof_hash_finish2(ctx, hash_chain, hash_size) != SECSuccess) return NULL;
	PK11_DestroyContext(ctx, PR_TRUE);
	return hash_chain;
}

PRUint8* advance_hash_chain(RecordProofInfo* rpi, PRUint8* hash_chain, PRUint8* hash){
	// Advance hash chain
	if(tlsproof_hash_begin2(rpi->ctx) != SECSuccess) return NULL;
	if(tlsproof_hash_op(rpi->ctx, &hash_chain_marker, sizeof(PRUint8)) != SECSuccess) return NULL;
	if(hash_chain != NULL){
		if(tlsproof_hash_op(rpi->ctx, hash_chain, rpi->hash_size) != SECSuccess) return NULL;
	}else{
		// Allocate space if necessary
		hash_chain = (PRUint8*) PORT_Alloc(rpi->hash_size);
	}
	if(tlsproof_hash_op(rpi->ctx, hash, rpi->hash_size) != SECSuccess) return NULL;
	if(tlsproof_hash_finish2(rpi->ctx, hash_chain, rpi->hash_size) != SECSuccess) return NULL;
	return hash_chain;
}

#ifdef TRACE
void printfProofParameters(ProofPar* proofPar){
	ssl_Trace("[TLS-N] == Proof Parameters: ==");
	ssl_Trace("[TLS-N] Hash Size: %u", proofPar->hash_size);
	ssl_Trace("[TLS-N] Salt Size: %u", proofPar->salt_size);
	ssl_Trace("[TLS-N] Chunk Size: %u", proofPar->chunk_size);
	ssl_Trace("[TLS-N] Start Time: %lli", proofPar->startTime);
	ssl_Trace("[TLS-N] Stop Time: %lli", proofPar->stopTime);
	ssl_Trace("[TLS-N] Number of Proof Nodes: %u", proofPar->num_proof_nodes);
	ssl_Trace("[TLS-N] Hash Type: %i", proofPar->hash_type);
	ssl_Trace("[TLS-N] Signature Length: %u", proofPar->sig_len);
	ssl_Trace("[TLS-N] Certificate Chain Length: %u", proofPar->cert_chain_len);
}

void printfHiddenPlaintextProofNode(HiddenPlaintextProofNode* plaintextProofNode){
	ssl_Trace("[TLS-N] -- Plaintext Proof Node: --");
	ssl_Trace("[TLS-N] Originated from Generator: %u", plaintextProofNode->gen_orig);
	ssl_Trace("[TLS-N] Record Size: %u", plaintextProofNode->len_record);
	ssl_Trace("[TLS-N] Num Salts: %u", plaintextProofNode->num_salts);
	ssl_Trace("[TLS-N] Num Hashes: %u", plaintextProofNode->num_hashes);
}

void printfPlaintextProofNode(PlaintextProofNode* plaintextProofNode){
	ssl_Trace("[TLS-N] -- Plaintext Proof Node: --");
	ssl_Trace("[TLS-N] Originated from Generator: %u", plaintextProofNode->gen_orig);
	ssl_Trace("[TLS-N] Record Size: %u", plaintextProofNode->len_record);
}



#endif

/*
static PRUint32 writeProofParameters(PRUint8* target, ProofPar* proofPar){
	PRUint32 offset = 0;
	WRITE_AT_OFFSET(target, offset, proofPar->hash_size);
	WRITE_AT_OFFSET(target, offset, proofPar->salt_size);
	WRITE_AT_OFFSET(target, offset, proofPar->chunk_size);
	WRITE_AT_OFFSET(target, offset, proofPar->startTime);
	WRITE_AT_OFFSET(target, offset, proofPar->stopTime);
	WRITE_AT_OFFSET(target, offset, proofPar->num_proof_nodes);
	WRITE_AT_OFFSET(target, offset, proofPar->hash_type);
	WRITE_AT_OFFSET(target, offset, proofPar->sig_len);
	WRITE_AT_OFFSET(target, offset, proofPar->cert_chain_len);
	return offset;
}

static PRUint32 writeProofNode(PRUint8* target, ProofNode* proofNode){
	PRUint32 offset = 0;
	WRITE_AT_OFFSET(target, offset, proofNode->node_type);
	return offset;
}

static PRUint32 writePlaintextProofNode(PRUint8* target, PlaintextProofNode* plaintextNode){
	PRUint32 offset = 0;
	WRITE_AT_OFFSET(target, offset, plaintextNode->gen_orig);
	WRITE_AT_OFFSET(target, offset, plaintextNode->len_record);
	WRITE_AT_OFFSET(target, offset, plaintextNode->num_salts);
	WRITE_AT_OFFSET(target, offset, plaintextNode->num_hashes);
	return offset;
}

static PRUint32 writeProofSalt(PRUint8* target, ProofSalt* proofSalt){
	PRUint32 offset = 0;
	WRITE_AT_OFFSET(target, offset, proofSalt->tree_level);
	WRITE_AT_OFFSET(target, offset, proofSalt->salt_index);
	return offset;
}

static PRUint32 writeProofMerkleNode(PRUint8* target, ProofMerkleNode* proofMerkleNode){
	PRUint32 offset = 0;
	WRITE_AT_OFFSET(target, offset, proofMerkleNode->tree_level);
	WRITE_AT_OFFSET(target, offset, proofMerkleNode->chunk_index);
	return offset;
}
*/

static SECStatus tlsproof_handleMessageResponse(sslSocket *ss, sslBuffer *origBuf)
{

#ifdef EV_MEASURE_COMP
	PRTime measure_start = PR_Now();
	// Total number of bytes
	PRUint32 record_bytes = 0;
	// Hidden number of bytes
	PRUint32 hidden_bytes = 0;
#endif

	int i;
	int j;
	SECStatus rv;
	SECItem sig;
	SECItem data;
	EvidenceMessage evMsg;
	PRUint16 offset = 0;
	PRUint32 proof_offset = 0;
	unsigned char *orderingVector;
	unsigned char *response = origBuf->buf;
	const unsigned int hash_size = tls13_GetHashSize(ss);
	unsigned char *hash_chain = NULL;
	// How many sent and received messages have been hashed into the hash chain
	PRUint32 hashed_recvd = 0;
	PRUint32 hashed_sent = 0;

	// Record end time
	PRTime timeStampStop = PR_Now();

	if(!ssl3_ExtensionNegotiated(ss,ssl_tls13_tls_proof_xtn)) return SECFailure;

	offset += TLS_PROOF_MESSAGE_TYPE_SIZE;

	READ_LEN_FROM_OFFSET(&evMsg, response, offset, EVIDENCE_MESSAGE_SIZE);

	// Signature
	sig.data = response+offset;
	offset += evMsg.sig_len;

	// Ordering Vector
	orderingVector = response+offset;
	offset += ceil_div8(evMsg.orderingVectorLen);

	PORT_Assert(offset == origBuf->len);

	sig.len = evMsg.sig_len;
	sig.type = siBuffer;
	

	// Construct the proof
	ProofPar proofPar;
	proofPar.hash_size = hash_size;
	proofPar.salt_size = ss->xtnData.salt_size;
	proofPar.chunk_size = ss->xtnData.chunk_size;
	proofPar.startTime = evMsg.timeStampStart;
	proofPar.stopTime = evMsg.timeStampStop;
	proofPar.hash_type = tls13_GetHash(ss);
	proofPar.sig_len = evMsg.sig_len;
	if(ss->tlsProofType & omit_cert_chain){
		proofPar.cert_chain_len = 0;
	}else{
		proofPar.cert_chain_len = ss->sec.peerCert->derCert.len;
	}

	if(ss->tlsProofType & merkle_hashes_proof){
		proofPar.num_proof_nodes = evMsg.orderingVectorLen;
	} else if (ss->tlsProofType & last_merkle_proof){
		proofPar.num_proof_nodes = 2;
		PORT_Assert(evMsg.orderingVectorLen >= 2);
	} else if (ss->tlsProofType & last_message_proof){
		proofPar.num_proof_nodes = 2;
		PORT_Assert(evMsg.orderingVectorLen >= 2);
	} else if (ss->tlsProofType & plaintext_proof){
		proofPar.num_proof_nodes = evMsg.orderingVectorLen;
	} else if (ss->tlsProofType & hidden_plaintext_proof){
		proofPar.num_proof_nodes = evMsg.orderingVectorLen;
	} else {
#ifdef TRACE
		SSL_TRC(10, ("Error: Unknown TLSProof Type."));
#endif		
	}


	// Allocate proof string
	PRUint32 proof_size = PROOF_PAR_SIZE + proofPar.sig_len + proofPar.cert_chain_len;
	unsigned char *proof_str = (unsigned char*) PORT_Alloc(proof_size);
	proof_offset = 0;
	WRITE_LEN_AT_OFFSET(proof_str, proof_offset, &proofPar, PROOF_PAR_SIZE);
	WRITE_LEN_AT_OFFSET(proof_str, proof_offset, sig.data, proofPar.sig_len);
	WRITE_LEN_AT_OFFSET(proof_str, proof_offset, ss->sec.peerCert->derCert.data, proofPar.cert_chain_len);
	PORT_Assert(proof_offset == proof_size);
	

	// Recomputing the hash chain
	for(i = 0; i < evMsg.orderingVectorLen; ++i){
		// 1 in ordering vector => sent by server => received by client
		PRBool received = (orderingVector[i/8] >> (i%8) ) & 1;
#ifdef TRACE
		if(ssl_trace > 50){
			ssl_Trace("Ordering Vector = %i", received);
			ssl_Trace("[TLS-N] %i received and %i sent.",  ss->tlsproofClientRecvLen, ss->tlsproofClientSentLen);
		}
#endif
		// Filter if no content
		if(ss->tlsproofClientRecvLen == 0 && ss->tlsproofClientSentLen == 0){
			return SECSuccess;
		}

		TLSProofClientRecording* recording = received ? &(ss->tlsproofClientRecv[hashed_recvd]) : &(ss->tlsproofClientSent[hashed_sent]);

#ifdef EV_MEASURE_COMP
		record_bytes += recording->plaintext_size;
#endif

		RecordProofInfo* rpi = init_proof_info(ss, recording->plaintext, recording->plaintext_size, received);
		// Compute the merkle hash if not precomputed
		if(recording->merkle_hash == NULL){
			recording->merkle_hash = (unsigned char*) PORT_Alloc(hash_size);
		
			if(compute_salt_tree(rpi, recording->salt_secret) != SECSuccess) return SECFailure;

			if(compute_merkle_tree(rpi, recording->merkle_hash) != SECSuccess) return SECFailure;

		}

#ifdef TRACE
		PRUint16 recording_len = received ? ss->tlsproofClientRecvLen : ss->tlsproofClientSentLen;
		PRUint16 used = received ? hashed_recvd : hashed_sent;
		PORT_Assert(recording_len > used);
		if(ssl_trace > 50){
			ssl_Trace("Using %i of %i.", used, recording_len);
			ssl_PrintBuf(ss, "Hashing = ", recording->merkle_hash, hash_size);
		}
#endif
		hash_chain = advance_hash_chain(rpi, hash_chain, recording->merkle_hash);
		if(hash_chain == NULL) return SECFailure;

		if(received){
			hashed_recvd++;
		} else {
			hashed_sent++;
		}

		
		if(ss->tlsProofType & merkle_hashes_proof){
			// Add another merkle proof node
			if( addMerkleProofNode(&proof_str, &proof_offset, &proof_size, recording->merkle_hash, hash_size)!= SECSuccess) return SECFailure;
		} else if (ss->tlsProofType & last_merkle_proof){
			if(i < evMsg.orderingVectorLen - 2){
				continue;
			} else if (i == evMsg.orderingVectorLen - 2){
				if(addHashChainNode(&proof_str, &proof_offset, &proof_size, hash_chain, hash_size) != SECSuccess) return SECFailure;
			} else if (i == evMsg.orderingVectorLen - 1){
				if(addMerkleProofNode(&proof_str, &proof_offset, &proof_size, recording->merkle_hash, hash_size)!= SECSuccess) return SECFailure;
			} else {
				PORT_Assert(PR_FALSE);
			}
		} else if (ss->tlsProofType & last_message_proof){
			if(i < evMsg.orderingVectorLen - 2){
				continue;
			} else if (i == evMsg.orderingVectorLen - 2){
				if(addHashChainNode(&proof_str, &proof_offset, &proof_size, hash_chain, hash_size) != SECSuccess) return SECFailure;
			} else if (i == evMsg.orderingVectorLen - 1){
				if(addPlaintextProofNode(&proof_str, &proof_offset, &proof_size, recording, received, proofPar.salt_size, proofPar.chunk_size)!= SECSuccess) return SECFailure;
			} else {
				PORT_Assert(PR_FALSE);
			}
		} else if (ss->tlsProofType & plaintext_proof){
			if(addPlaintextProofNode(&proof_str, &proof_offset, &proof_size, recording, received, proofPar.salt_size, proofPar.chunk_size)!= SECSuccess) return SECFailure;
		} else if (ss->tlsProofType & hidden_plaintext_proof){
			// TODO: Consistent data types for num_chunks, salt_size, hash_size etc. Replace _t types
			// Find sensitive chunks
			if(find_sensitive_chunks(rpi) != SECSuccess) return SECFailure;
			if(rpi->num_hidden_chunks == 0){
				// No hidden chunks => plaintext node
				if(addPlaintextProofNode(&proof_str, &proof_offset, &proof_size, recording, received, proofPar.salt_size, proofPar.chunk_size)!= SECSuccess) return SECFailure;
			} else if(rpi->num_hidden_chunks == rpi->num_chunks){
				// All chunks hidde => merkle hash node
				if(addMerkleProofNode(&proof_str, &proof_offset, &proof_size, recording->merkle_hash, hash_size)!= SECSuccess) return SECFailure;
			} else {
				// Mixed Node
		
				// ----- Compute necessary hashes ------
				// Salts have already been computed during evidence verification
				if(compute_proof_merkle_hashes(rpi) != SECSuccess) return SECFailure;
				
				// ----- Compute the proof salts ----
				if(compute_proof_salts(rpi, recording->salt_secret) != SECSuccess) return SECFailure;
				PRUint8** proof_salts = rpi->salts;

				// ---- Form proof str ----
				ProofNode proofNode;
				proofNode.node_type = hidden_plaintext_node;

				HiddenPlaintextProofNode plaintextNode;
				plaintextNode.gen_orig = received;
				plaintextNode.len_record = recording->plaintext_size;
				plaintextNode.num_salts = rpi->num_salts;
				plaintextNode.num_hashes = rpi->num_hashes;

	
				PORT_Assert(proof_offset == proof_size);
				// Proof Node & PlaintextProofNode
				proof_size += PROOF_NODE_SIZE + HIDDEN_PLAINTEXT_PROOF_NODE_SIZE;
				// Salt Locs and Proof Salts
				proof_size += rpi->num_salts * PROOF_SALT_SIZE + rpi->num_salts * rpi->salt_size;
				// Hash Locs and Proof Hashes
				proof_size += rpi->num_hashes * PROOF_MERKLE_NODE_SIZE + rpi->num_hashes * rpi->hash_size;
				// Compressed (without censored chunks) record length
				proof_size += compute_compressed_record_length(rpi);

				proof_str = (unsigned char*) PORT_Realloc(proof_str, proof_size);
				WRITE_LEN_AT_OFFSET(proof_str, proof_offset, &proofNode, PROOF_NODE_SIZE);
				// Plaintext Node
				WRITE_LEN_AT_OFFSET(proof_str, proof_offset, &plaintextNode, HIDDEN_PLAINTEXT_PROOF_NODE_SIZE);
				// Salt Locations
				for(j = 0; j < rpi->num_salts; ++j){
					WRITE_LEN_AT_OFFSET(proof_str, proof_offset, &(rpi->salt_locs[j]), PROOF_SALT_SIZE);
					//proof_offset += writeProofSalt(proof_str+proof_offset, rpi->salt_locs[j]);	
				}
				// Proof Salts
				WRITE_LEN_AT_OFFSET(proof_str, proof_offset, proof_salts[0], rpi->num_salts * rpi->salt_size);
				// Hash Locations
				for(j = 0; j < rpi->num_hashes; ++j){
					WRITE_LEN_AT_OFFSET(proof_str, proof_offset, &(rpi->hash_locs[j]), PROOF_MERKLE_NODE_SIZE);
				}
				// Proof Hashes
				WRITE_LEN_AT_OFFSET(proof_str, proof_offset, rpi->proof_merkle_hashes[0], rpi->num_hashes * rpi->hash_size);
				// Only include uncensored record parts
				PRUint16 chunk_index;
				PRUint16 chunk_length;
				for(chunk_index = 0; chunk_index < rpi->num_chunks; ++chunk_index){
					chunk_length = get_chunk_length2(rpi, chunk_index);
					if(!is_hidden_chunk(rpi->hidden_chunk_ids, rpi->num_hidden_chunks, chunk_index)){
						PORT_Memcpy(proof_str+proof_offset, rpi->record + chunk_index * rpi->chunk_size, chunk_length);
						proof_offset += chunk_length;
					}
#ifdef EV_MEASURE_COMP
					else{
						hidden_bytes += chunk_length;
					}
#endif

				}
				WRITE_ZEROES_AT_OFFSET(proof_str, proof_offset, compute_compressed_record_padding(rpi));
			 

				PORT_Assert(proof_offset == proof_size);				
				
			}
		
		}
		free_rpi(rpi);
	}
	
#ifdef TRACE
	if(ssl_trace > 50){
		ssl_PrintBuf(ss, "Hash chain value = ", hash_chain, hash_size);
	}
#endif

	// Testing the Signature
	// First constructing the signed data
	offset = 0;
	data.type = siBuffer;
	data.len = hash_size;
	data.data = (unsigned char *) PORT_Alloc(data.len);

	PK11Context *ctx = PK11_CreateDigestContext(ssl3_HashTypeToOID(proofPar.hash_type));
	if(tlsproof_hash_begin2(ctx) != SECSuccess) return SECFailure;
	if(tlsproof_hash_op(ctx, hash_chain, hash_size) != SECSuccess) return SECFailure;
	if(tlsproof_hash_op(ctx, &evMsg.timeStampStart, sizeof(evMsg.timeStampStart)) != SECSuccess) return SECFailure;
	if(tlsproof_hash_op(ctx, &evMsg.timeStampStop, sizeof(evMsg.timeStampStop)) != SECSuccess) return SECFailure;
	if(tlsproof_hash_op(ctx, &proofPar.salt_size, sizeof(proofPar.salt_size)) != SECSuccess) return SECFailure;
	if(tlsproof_hash_op(ctx, &proofPar.chunk_size, sizeof(proofPar.chunk_size)) != SECSuccess) return SECFailure;
	if(tlsproof_hash_op(ctx, &proofPar.hash_type, sizeof(SSLHashType)) != SECSuccess) return SECFailure;
	if(tlsproof_hash_finish2(ctx, data.data, hash_size) != SECSuccess) return SECFailure;
	PK11_DestroyContext(ctx, PR_TRUE);


	SECKEYPublicKey *key = CERT_ExtractPublicKey(ss->sec.peerCert);
	PORT_Assert(key != NULL);

	rv = PK11_Verify(key, &sig, &data, NULL);
	if(rv != SECSuccess){
#ifdef TRACE
		ssl_Trace("[TLS-N] !!! Signature Verification Failed During Evidence Generation!!!\n");
#endif
		// TODO: Cleanup here
		return SECFailure;
	}
#ifdef TRACE
	SSL_TRC(10, ("[TLS-N] Signature Verification: OK!\n"));
#endif

	if(abs(evMsg.timeStampStart - ss->tlsproofTimeStampStart) > TLS_PROOF_WARN_TIME_DIFF){
#ifdef TRACE
		ssl_Trace("[TLS-N] Warning: Discrepenancy in start timestamps.\n");
#endif
	}
	if(abs(evMsg.timeStampStop - timeStampStop) > TLS_PROOF_WARN_TIME_DIFF){
#ifdef TRACE
		ssl_Trace("[TLS-N] Warning: Discrepenancy in stop timestamps.\n");
#endif
	}



	//Flush the buffer because it is not destined to application layer
	origBuf->len = 0;

	SECKEY_DestroyPublicKey(key);
	PORT_Free(data.data);
	PORT_Free(hash_chain);
#ifdef EV_MEASURE_COMP
	PRTime measure_stop = PR_Now();
	printf("[Measure-Generation] %lu, %i, %u, %u, %u, %u, %u, %u\n", measure_stop - measure_start, record_bytes, proofPar.chunk_size, proofPar.salt_size, proofPar.hash_size, proof_size - record_bytes, hidden_bytes, evMsg.orderingVectorLen);
#endif
	//Call the user define callback to handle the signature
	if(ss->tlsProofReturnCallBack != NULL){
		rv = (*ss->tlsProofReturnCallBack)(proof_str, proof_size);
	}

	return SECSuccess;
}


// ------------ Proof Verification -------------

SECStatus SSL_TLSProofCheckProof(unsigned char *proof_str, unsigned int proof_size){

#ifdef EV_MEASURE_COMP
	PRTime measure_start = PR_Now();
#endif
	ProofPar proofPar;
	PRUint32 proof_offset = 0;
	PRUint8* hash_chain = NULL;
	// Data for signature
	SECItem data;
	CERTCertificate* cert;
	// Signature
	SECItem sig;
	SECItem certbuf;
	int i;
	ProofNode proofNode;
	bzero(&proofNode, sizeof(proofNode));
	PlaintextProofNode plaintextNode;
	bzero(&plaintextNode, sizeof(plaintextNode));
	HiddenPlaintextProofNode hiddenPlaintextNode;
	bzero(&hiddenPlaintextNode, sizeof(hiddenPlaintextNode));
	PRUint8* plaintext;
	PRUint8* salt_secret;
	int num_proof_node;

	PORT_Assert(proof_str != NULL && proof_size > PROOF_PAR_SIZE);

	// Parse main structure
	READ_LEN_FROM_OFFSET(&proofPar, proof_str, proof_offset, PROOF_PAR_SIZE);

#ifdef TRACE
	if(ssl_trace > 40){
		printfProofParameters(&proofPar);
	}
#endif

	// Check timestamps
	if(proofPar.startTime > proofPar.stopTime){
		return SECFailure;
	}

	// Parse signature
	sig.type = siBuffer;
	sig.data = proof_str+proof_offset;
	sig.len = proofPar.sig_len;
	proof_offset += proofPar.sig_len;
	
	// Parse certificate
	certbuf.type = siBuffer;
	certbuf.data = proof_str+proof_offset;
	certbuf.len = proofPar.cert_chain_len;	
	proof_offset += proofPar.cert_chain_len;
	if(proofPar.cert_chain_len != 0){
		cert = CERT_DecodeDERCertificate(&certbuf, PR_FALSE, NULL);

		// Check against CA
		// TODO: Move this
		secuPWData pwdata;
		pwdata.source = PW_PLAINTEXT;
		pwdata.data = "";
		if(CERT_VerifyCertNow(CERT_GetDefaultCertDB(), cert, PR_TRUE, certUsageSSLServer, &pwdata) != SECSuccess){
#ifdef TRACE
			ssl_Trace("Invalid Certificate.\n");
#endif
			return SECFailure;
		}
	}else{
#ifdef TRACE
		ssl_Trace("[TLS-N] Warning: This proof contains no certificate chain. It is only trustworthy if you know the generator's (server's) public key.\n");
#endif
	}

	
	// Loop over proof nodes
	for(num_proof_node = 0; num_proof_node < proofPar.num_proof_nodes; ++num_proof_node){
		READ_LEN_FROM_OFFSET(&proofNode, proof_str, proof_offset, PROOF_NODE_SIZE);
		if(proofNode.node_type == hash_chain_node){
				// Hash Chain Node
				if(hash_chain == NULL){
					// First value => Copy state
					hash_chain = (PRUint8*) PORT_Alloc(proofPar.hash_size);
					READ_LEN_FROM_OFFSET(hash_chain, proof_str, proof_offset, proofPar.hash_size)
				} else {
					// A hash chain value can only be given to initialize not to update
					return SECFailure;
				}
		} else if(proofNode.node_type == merkle_hash_node){
				// New hash of a record
				hash_chain = advance_hash_chain2(hash_chain, proof_str+proof_offset, proofPar.hash_size, proofPar.hash_type);

				proof_offset += proofPar.hash_size;
		} else if(proofNode.node_type == plaintext_node){
				READ_LEN_FROM_OFFSET(&plaintextNode, proof_str, proof_offset, PLAINTEXT_PROOF_NODE_SIZE);
#ifdef TRACE
				if(ssl_trace > 50){
					// Print
					printfPlaintextProofNode(&plaintextNode);
				}
#endif
				plaintext = proof_str+proof_offset;
				proof_offset += plaintextNode.len_record + recordPaddingSize(plaintextNode.len_record, proofPar.chunk_size);
				salt_secret = proof_str+proof_offset;
				proof_offset += proofPar.salt_size;

				RecordProofInfo* rpi = init_proof_info_from_plaintext_proof(&proofPar, &plaintextNode, plaintext, NULL, NULL, NULL);
			

				#ifdef TRACE
					my_print_buf("[TLS-N] Salt Secret: %s", salt_secret, proofPar.salt_size, 60);
				#endif
		
				if(compute_salt_tree(rpi, salt_secret) != SECSuccess) return SECFailure;

				PRUint8 merkle_hash[proofPar.hash_size];
				if(compute_merkle_tree(rpi, merkle_hash) != SECSuccess) return SECFailure;
				#ifdef TRACE
					my_print_buf("[TLS-N] Computed merkle hash during proof verification: %s", merkle_hash, proofPar.hash_size, 60);
					my_print_buf("[TLS-N] Plaintext: %s", plaintext, plaintextNode.len_record, 60);
				#endif
	
				hash_chain = advance_hash_chain(rpi, hash_chain, merkle_hash);
				free_rpi(rpi);

		} else if(proofNode.node_type == hidden_plaintext_node) {
				READ_LEN_FROM_OFFSET(&hiddenPlaintextNode, proof_str, proof_offset, HIDDEN_PLAINTEXT_PROOF_NODE_SIZE);
#ifdef TRACE
				if(ssl_trace > 50){
					// Print
					printfHiddenPlaintextProofNode(&hiddenPlaintextNode);
				}
#endif
				ProofSalt *salt_locs = (ProofSalt*) PORT_Alloc(hiddenPlaintextNode.num_salts * sizeof(ProofSalt));
				for(i = 0; i < hiddenPlaintextNode.num_salts; ++i){
					READ_LEN_FROM_OFFSET(&(salt_locs[i]), proof_str, proof_offset, PROOF_SALT_SIZE);
				}

				PRUint8** proof_salts = (PRUint8**) PORT_Alloc(hiddenPlaintextNode.num_salts * sizeof(PRUint8*));
				for(i = 0; i < hiddenPlaintextNode.num_salts; ++i){
					proof_salts[i] = (PRUint8*) proof_str+proof_offset;
					proof_offset += proofPar.salt_size;
				}
				
				ProofMerkleNode *hash_locs = (ProofMerkleNode *) PORT_Alloc(hiddenPlaintextNode.num_hashes * sizeof(ProofMerkleNode));
				for(i = 0; i < hiddenPlaintextNode.num_hashes; ++i){
					READ_LEN_FROM_OFFSET(&(hash_locs[i]), proof_str, proof_offset, PROOF_MERKLE_NODE_SIZE);
				}

				PRUint8** proof_merkle_hashes = (PRUint8**) PORT_Alloc(hiddenPlaintextNode.num_hashes * sizeof(PRUint8*));
				for(i = 0; i < hiddenPlaintextNode.num_hashes; ++i){
					proof_merkle_hashes[i] = proof_str+proof_offset;
					proof_offset += proofPar.hash_size;
				}

				RecordProofInfo* rpi = init_proof_info_from_proof(&proofPar, &hiddenPlaintextNode, NULL, hash_locs, proof_merkle_hashes, salt_locs);

				PRUint8 *compressed_record = proof_str+proof_offset;
				proof_offset += compute_compressed_record_length(rpi);

				
				if(inflate_record(rpi, compressed_record) != SECSuccess) return SECFailure;

#ifdef TRACE
				my_print_buf("[TLS-N] Plaintext: %s", rpi->record, hiddenPlaintextNode.len_record, 60);
#endif
			
				
				if(compute_salts_from_proof_salts(rpi, proof_salts) != SECSuccess) return SECFailure;
				#ifdef TRACE
					if(ssl_trace >= 60){
						PRUint16 salt_id = 0;
						for(salt_id = 0; salt_id < rpi->num_chunks; ++salt_id){
							my_print_buf("[TLS-N] During Verification: Salt: %s", rpi->salts[salt_id], proofPar.salt_size, 60);
						}
						PRUint16 hash_id = 0;
						for(hash_id = 0; hash_id < rpi->num_hashes; ++hash_id){
							ssl_Trace("[TLS-N] During Verification: Hash %i: Level = %i, Index = %i", hash_id, rpi->hash_locs[hash_id].tree_level, rpi->hash_locs[hash_id].chunk_index);
							my_print_buf("[TLS-N] Hash %s", rpi->proof_merkle_hashes[hash_id], proofPar.hash_size, 60);
						}
					}
				#endif
	
				// -- Compute merkle hash ---
				PRUint8 outbuf[rpi->hash_size];

				if(compute_merkle_tree_from_proof(rpi, outbuf) != SECSuccess) return SECFailure;

				#ifdef TRACE
					my_print_buf("[TLS-N] Computed merkle hash during proof verification: %s",outbuf, proofPar.hash_size, 60);
				#endif
	
				hash_chain = advance_hash_chain(rpi, hash_chain, outbuf);
				free_rpi(rpi);
				PORT_Free(proof_salts);
				
		}else{
#ifdef TRACE
			SSL_TRC(10, ("[TLS-N] Invalid Proof Format!"));
#endif			
			return SECFailure;
		}
	}

	PORT_Assert(hash_chain != NULL);

	if(proofPar.cert_chain_len != 0){
		// Testing the Signature
		// First constructing the signed data
		data.type = siBuffer;
		data.len = proofPar.hash_size;
		data.data = (unsigned char *) PORT_Alloc(data.len);

		PK11Context *ctx = PK11_CreateDigestContext(ssl3_HashTypeToOID(proofPar.hash_type));
		if(tlsproof_hash_begin2(ctx) != SECSuccess) return SECFailure;
		if(tlsproof_hash_op(ctx, hash_chain, proofPar.hash_size) != SECSuccess) return SECFailure;
		if(tlsproof_hash_op(ctx, &proofPar.startTime, sizeof(proofPar.startTime)) != SECSuccess) return SECFailure;
		if(tlsproof_hash_op(ctx, &proofPar.stopTime, sizeof(proofPar.stopTime)) != SECSuccess) return SECFailure;
		if(tlsproof_hash_op(ctx, &proofPar.salt_size, sizeof(proofPar.salt_size)) != SECSuccess) return SECFailure;
		if(tlsproof_hash_op(ctx, &proofPar.chunk_size, sizeof(proofPar.chunk_size)) != SECSuccess) return SECFailure;
		if(tlsproof_hash_op(ctx, &proofPar.hash_type, sizeof(SSLHashType)) != SECSuccess) return SECFailure;
		if(tlsproof_hash_finish2(ctx, data.data, proofPar.hash_size) != SECSuccess) return SECFailure;
		PK11_DestroyContext(ctx, PR_TRUE);

#ifdef TRACE
		my_print_buf("[TLS-N] Final hash chain during proof verification: %s", hash_chain, proofPar.hash_size, 20);
#endif
		
#ifdef TRACE
		my_print_buf("[TLS-N] Hash to be signed: %s", data.data, data.len, 20);
		my_print_buf("[TLS-N] Signature: %s", sig.data, sig.len, 20);
#endif

		SECKEYPublicKey *key = CERT_ExtractPublicKey(cert);
		PORT_Assert(key != NULL);

		if(PK11_Verify(key, &sig, &data, NULL) != SECSuccess){
#ifdef TRACE
			SSL_TRC(10, ("[TLS-N] Error: Signature Verification failed during Proof Verification!"));
#endif 
			// TODO: Cleanup here
			return SECFailure;
		}
#ifdef TRACE
		SSL_TRC(15, ("[TLS-N] Proof Verification: OK!"));
#endif 

		PORT_Free(data.data);
		SECKEY_DestroyPublicKey(key);
		CERT_DestroyCertificate(cert);
}

	PORT_Assert(proof_offset == proof_size);
	if(hash_chain != NULL){
		PORT_Free(hash_chain);
	}

#ifdef EV_MEASURE_COMP
	PRTime measure_stop = PR_Now();
	printf("[Measure-Verification] %lu, %i, %u, %u, %u\n", measure_stop - measure_start, proofPar.chunk_size, proofPar.salt_size, proofPar.hash_size, proof_size);
#endif

	return SECSuccess;
}


SECStatus SSL_TLSProofSetSaltSize(PRFileDesc *fd, PRUint16 client_prop_salt_size){
    sslSocket *ss = ssl_FindSocket(fd);

    if (!ss) return SECFailure;

    if(!ss->opt.enableTLSProof) return SECFailure;

    ss->client_prop_salt_size = client_prop_salt_size;

    return SECSuccess;
}


SECStatus SSL_TLSProofSetChunkSize(PRFileDesc *fd, PRUint16 client_prop_chunk_size){
    sslSocket *ss = ssl_FindSocket(fd);

    if (!ss) return SECFailure;

    if(!ss->opt.enableTLSProof) return SECFailure;

    ss->client_prop_chunk_size = client_prop_chunk_size;

    return SECSuccess;
}



/*Set the callback*/
SECStatus SSL_TLSProofSetReturnCallBack(PRFileDesc *fd, SSLTLSProofReturnCallBack callback, PRUint8 proof_type)
{
	sslSocket *ss = ssl_FindSocket(fd);

	if (!ss) return SECFailure;

	if(!ss->opt.enableTLSProof) return SECFailure;

	ss->tlsProofReturnCallBack = callback;

	ss->tlsProofType = proof_type;

	return SECSuccess;
}





/*Update the Merkle root with a new specify message. It is call whenever a server send or receive a message
 * The message is passed by sslBuffer and the boolean received should be set if it is a received message*/
SECStatus tlsproof_addMessageToProof(sslSocket *ss, const PRUint8 *record, const PRUint16 record_length, PRBool received)
{

#ifdef EV_MEASURE_COMP
	PRTime measure_start = PR_Now();
	PRTime merkle_tree_start, merkle_tree_stop, salt_tree_start, salt_tree_stop;
	merkle_tree_start = merkle_tree_stop = salt_tree_start = salt_tree_stop = 0;
#endif

	// TODO: Move to post_handshake
	if(ss->tlsproofTimeStampStart == 0){
		ss->tlsproofTimeStampStart = PR_Now();
	}

	if(!record) return SECFailure;

	// TODO: Replace printf with ssl_trace
	SECStatus rv;
	RecordProofInfo* rpi = init_proof_info(ss, record, record_length, received);
	if(rpi == NULL) return SECFailure;
	PRUint8 merkle_hash[rpi->hash_size];


	// Get traffic secret
	PK11SymKey * key;
	if(ss->sec.isServer){
		key = received ? ss->ssl3.crSpec->client.write_key : ss->ssl3.cwSpec->server.write_key;
	} else {
		key = received ? ss->ssl3.crSpec->server.write_key : ss->ssl3.cwSpec->client.write_key;
	}
	if(PK11_ExtractKeyValue(key) != SECSuccess || PK11_GetKeyData(key)->data == NULL){
		printf("Error! The traffic secret is empty!\n");
		return SECFailure;
	}

	// Generate intermediate key 
	// Secret + Nonce
	sslSequenceNumber nonce = received ? ss->ssl3.crSpec->read_seq_num : ss->ssl3.cwSpec->write_seq_num;
#ifdef TRACE
	SSL_TRC(50, ("[TLS-N] Nonce: %lu\n", nonce));
#endif
	PK11SymKey* tmp_secret;

	tmp_secret = pk11_ConcatenateBaseAndData(key, (unsigned char*) &nonce, sizeof(sslSequenceNumber), tls13_GetHkdfMechanism(ss), CKA_DERIVE);
	if(PK11_ExtractKeyValue(tmp_secret) != SECSuccess  || PK11_GetKeyData(tmp_secret)->data == NULL){
		printf("Error! Temporary Secret not properly generated!\n");
		return SECFailure;
	}

	// Generate the salt secret
	const char kHkdfPurposeSaltSecret[] = "salt secret";
	PK11SymKey* salt_secret;
    rv = tls13_HkdfExpandLabel(tmp_secret, rpi->hash_type,
                               NULL, 0,
                               kHkdfPurposeSaltSecret, strlen(kHkdfPurposeSaltSecret),
                               tls13_GetHkdfMechanism(ss),
                               rpi->salt_size, &salt_secret);
    if (rv != SECSuccess) {
        return SECFailure;
    }

	// Compute salts
	PORT_Assert(rpi->hash_size >= 2 * rpi->salt_size);
	// level 0 = salt secret
#ifdef TRACE
	SSL_TRC(50, ("[TLS-N] Salt Index: %i, Salt Tree Levels: %i\n", rpi->salt_index, rpi->tree_levels));
#endif
	if(PK11_ExtractKeyValue(salt_secret) != SECSuccess || PK11_GetKeyData(salt_secret)->data == NULL){
		printf("Error! Salt Secret not properly generated!\n");
		return SECFailure;
	}

	// A client saving the plaintexts does not need to do this
	if(ss->sec.isServer || (!requires_plaintext_saving(ss->tlsProofType))){
	
#ifdef EV_MEASURE_COMP
		salt_tree_start = PR_Now();
#endif
		rv = compute_salt_tree(rpi, PK11_GetKeyData(salt_secret)->data);
#ifdef EV_MEASURE_COMP
		salt_tree_stop = PR_Now();
#endif
		if (rv != SECSuccess) {
			return SECFailure;
		}

	#ifdef TRACE
		if(ssl_trace >= 50){
			ssl_Trace("Salt Size: %u", rpi->salt_size);
			int i;
			for(i = 0; i < rpi->num_chunks; ++i){
				ssl_PrintBuf(ss, "[TLS-N] Salt:", rpi->salts[i], rpi->salt_size);
			}
		}
	#endif

#ifdef EV_MEASURE_COMP
		merkle_tree_start = PR_Now();
#endif
		rv = compute_merkle_tree(rpi, merkle_hash);
#ifdef EV_MEASURE_COMP
		merkle_tree_stop = PR_Now();
#endif
		if (rv != SECSuccess) {
			return SECFailure;
		}


	#ifdef TRACE
		if (ssl_trace >= 25){
			ssl_PrintBuf(ss, "Message Hash = ", merkle_hash, rpi->hash_size);
		}
	#endif
	}

	// The server manages the ordering vector and keeps the hash chain
	if(ss->sec.isServer){

		// Advance hash_chain
		ss->tlsproofMerkleRoot = advance_hash_chain(rpi, ss->tlsproofMerkleRoot, merkle_hash);
		if(ss->tlsproofMerkleRoot == NULL) return SECFailure;

		// Manage Ordering Vector
		if(ss->tlsproofOrderingVectorLen%8 == 0){
			// Reallocate
			ss->tlsproofOrderingVector = PORT_Realloc(ss->tlsproofOrderingVector, ss->tlsproofOrderingVectorLen + 1);
			// Zero last part
			ss->tlsproofOrderingVector[ss->tlsproofOrderingVectorLen/8] = 0;
		}
		// Server message => add a 1
		if(! received){
			ss->tlsproofOrderingVector[ss->tlsproofOrderingVectorLen/8] |= 1 << (ss->tlsproofOrderingVectorLen%8);
		}
		ss->tlsproofOrderingVectorLen++;
#ifdef TRACE
		if (ssl_trace >= 25){
			ssl_PrintBuf(ss, "New Hash Chain Value: ", ss->tlsproofMerkleRoot, rpi->hash_size);
		}
#endif
	} else {
		// The client remembers the hashes of the different records
		TLSProofClientRecording** recording_ptr = received ? &ss->tlsproofClientRecv: &ss->tlsproofClientSent;
		PRUint32* len_ptr = received ? &ss->tlsproofClientRecvLen : &ss->tlsproofClientSentLen;

#ifdef TRACE
		if (ssl_trace >= 25){
			ssl_Trace("[TLS-N] Adding element %i for %i: ", *len_ptr, received);
		}
#endif

		// Reallocate
		*recording_ptr = (TLSProofClientRecording*) PORT_Realloc(*recording_ptr, (*len_ptr + 1) * sizeof(TLSProofClientRecording));
		bzero(&((*recording_ptr)[*len_ptr]), sizeof(TLSProofClientRecording));

		// Check if the client has to save the plaintext
		if(requires_plaintext_saving(ss->tlsProofType)){
			// Save record size
			(*recording_ptr)[*len_ptr].plaintext_size = record_length;
			
			// Allocate space for record + 1 for zero-byte for regexes later
			(*recording_ptr)[*len_ptr].plaintext = (unsigned char*) PORT_Alloc(record_length + 1);
			// Save record
			PORT_Memcpy((*recording_ptr)[*len_ptr].plaintext, record, record_length);
			// Set Zero Byte
			(*recording_ptr)[*len_ptr].plaintext[record_length] = '\0';
			// Allocate space for salt secret 
			(*recording_ptr)[*len_ptr].salt_secret = (unsigned char*) PORT_Alloc(rpi->salt_size);
			// Save salt secret 
			PORT_Memcpy((*recording_ptr)[*len_ptr].salt_secret, PK11_GetKeyData(salt_secret)->data, rpi->salt_size);
			(*recording_ptr)[*len_ptr].merkle_hash = NULL;
		}else{
			// Allocate space for merkle hash 
			(*recording_ptr)[*len_ptr].merkle_hash = (unsigned char*) PORT_Alloc(rpi->hash_size);
			// Save merkle hash
			PORT_Memcpy((*recording_ptr)[*len_ptr].merkle_hash, merkle_hash, rpi->hash_size);
			(*recording_ptr)[*len_ptr].salt_secret = NULL;
			(*recording_ptr)[*len_ptr].plaintext = NULL;
			(*recording_ptr)[*len_ptr].plaintext_size = 0;
		}
		
		// Increment len counter
		(*len_ptr)++;
	}

	
	// Free secrets
	PK11_FreeSymKey(tmp_secret);
	PK11_FreeSymKey(salt_secret);

#ifdef EV_MEASURE_COMP
	if(!ss->sec.isServer){
		PRTime measure_stop = PR_Now();
		printf("[Measure-Latency] %lu, %i, %u, %u, %u\n", measure_stop - measure_start, record_length, rpi->chunk_size, rpi->salt_size, rpi->hash_size);
	}else{
		PRTime measure_stop = PR_Now();
		printf("[Measure-Latency] %lu, %i, %u, %u, %u, %lu, %lu\n", measure_stop - measure_start, record_length, rpi->chunk_size, rpi->salt_size, rpi->hash_size, salt_tree_stop-salt_tree_start, merkle_tree_stop-merkle_tree_start);
	}
#endif
	free_rpi(rpi);

	return SECSuccess;
}


#ifdef TRACE
void my_print_buf(char* fmt_msg, const PRUint8* buf, PRUint32 buf_size, PRUint8 ssl_limit){
    if(ssl_trace >= ssl_limit){
        int i;
        char hexbuf[2 *buf_size+1];
        for(i = 0; i < buf_size; ++i){
            snprintf(hexbuf + 2*i, sizeof(hexbuf), "%02x", buf[i]);
        }
        ssl_Trace(fmt_msg, hexbuf);
    }
}
#endif

// TODO: ssl_DupSocket
