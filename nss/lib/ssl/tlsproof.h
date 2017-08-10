#ifndef __tlsproof_h_
#define __tlsproof_h_
#include "prtime.h"
#include "sslt.h"
#include "tlsproofstr.h"
#include "hasht.h"
#include "alghmac.h"
#include "sechash.h"



// The defaults for salt and chunk size
// Salt size 128 bit of security
#define SALT_SIZE 16
// Make this configurable in the handshake
#define CHUNK_SIZE 16383


// Time difference in microseconds to trigger a warning
#define TLS_PROOF_WARN_TIME_DIFF 1000000

#define WRITE_AT_OFFSET(target, offset, val)\
{ \
	PORT_Memcpy(target + offset, &(val), sizeof(val)); \
	offset += sizeof(val); \
}

#define WRITE_LEN_AT_OFFSET(target, offset, val, len)\
{ \
	PORT_Memcpy(target + offset, val, len); \
	offset += len; \
}

#define WRITE_ZEROES_AT_OFFSET(target, offset, len)\
{ \
	PORT_Memset(target + offset, 0, len); \
	offset += len; \
}

#define READ_LEN_FROM_OFFSET(target, buffer, offset, len)\
{ \
	PORT_Memcpy(target, buffer + offset, len); \
	offset += len; \
}


void my_print_buf(char* fmt_msg, const PRUint8* buf, PRUint32 buf_size, PRUint8 ssl_limit);


SECStatus tlsproof_HandleMessage(sslSocket *ss, sslBuffer *origBuf);
SECStatus tlsproof_addMessageToProof(sslSocket *ss, const PRUint8 *record, const PRUint16 rec_len,  PRBool received);
SECStatus SSL_TLSProofCheckProof(unsigned char *proof_str, unsigned int proof_size);
SECStatus tlsproof_sendEvidenceOnClose(sslSocket *ss);


// Proof paramaters
#define PROOF_PAR_SIZE (sizeof(PRUint16) + sizeof(PRUint16) + sizeof(PRUint16) + sizeof(PRUint16) + sizeof(PRUint64) + sizeof(PRUint64)  + sizeof(PRUint16) + sizeof(PRUint16) + sizeof(SSLHashType))
typedef struct ProofParStr{
	PRUint16 hash_size;
	PRUint16 salt_size;
	PRUint16 chunk_size;
	PRUint16 num_proof_nodes;
	PRUint64 startTime;
	PRUint64 stopTime;
	PRUint16 sig_len; // Signature is directly after this struct
	PRUint16 cert_chain_len; // Certificate Chain is after the signature
	SSLHashType hash_type;
} ProofPar;

#define PROOF_NODE_SIZE 1
typedef struct ProofNodeStr{
	TLSProofNodeType node_type; // Can be Hash_chain, plaintext + salts, merkle_hash
} ProofNode;

// Order: Struct, Plaintext, Salt Secret
#define PLAINTEXT_PROOF_NODE_SIZE (sizeof(PRUint16) + sizeof(PRUint8))
typedef struct PlaintextProofNodeStr{
	PRUint16 len_record;
	PRUint8 gen_orig; // Record sent by the generator
} PlaintextProofNode;

// Order: Struct, Salts (Loc, Val), Hashes (Loc, Val), Uncensored Plaintext
#define HIDDEN_PLAINTEXT_PROOF_NODE_SIZE (sizeof(PRUint16) + sizeof(PRUint16) + sizeof(PRUint16) + sizeof(PRUint8))
typedef struct HiddenPlaintextProofNodeStr{
	PRUint16 len_record;
	PRUint16 num_salts; 
	PRUint16 num_hashes;
	PRUint8 gen_orig; // Record sent by the generator
} HiddenPlaintextProofNode;


#define EVIDENCE_MESSAGE_SIZE (sizeof(PRTime) + sizeof(PRTime) + sizeof(PRUint16) + sizeof(PRUint16))
typedef struct EvidenceMessageStr{
	PRTime timeStampStart;
	PRTime timeStampStop;
	PRUint16 sig_len;
	PRUint16 orderingVectorLen;
} EvidenceMessage;

// Proof paramaters
typedef struct RecordProofInfoStr{
	const PRUint16 hash_size;
	const PRUint16 salt_size;
	const PRUint16 chunk_size;
	const SSLHashType hash_type;
	const PRUint8* record;
	PRUint16 record_length;
	const PRUint16 num_chunks; 
	const PRUint16 tree_levels;
	const PRUint8 gen_orig;
	PRUint16 salt_index;
	PRUint16 chunk_index;
	PRUint8** salts;
	PRUint16 num_hashes;
	ProofMerkleNode* hash_locs;
	PRUint8** proof_merkle_hashes;
	PRUint16* hidden_chunk_ids;
	PRUint16 num_hidden_chunks;
	ProofSalt* salt_locs;
	PRUint16 num_salts;
	PRBool initialized_from_proof;
	PK11Context *ctx;
	const CK_MECHANISM_TYPE hkdf_mechanism;
	HMACContext *hmac;
	PRUint8* hmac_info;
	PRUint8 hmac_info_len;
} RecordProofInfo;

#endif
