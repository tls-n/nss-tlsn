#ifndef __tlsproofstr_h_
#define __tlsproofstr_h_

    // Save the information necessary for proof generation
    typedef struct TLSProofClientRecordingStr{
        // Content of records
        unsigned char* plaintext;
        // Size of records
        PRUint16 plaintext_size;
        unsigned char* merkle_hash;
        // Salt Secrets
        unsigned char* salt_secret;
    } TLSProofClientRecording;


typedef enum {
    merkle_hashes_proof = 1,
    last_merkle_proof = 2,
    last_message_proof = 4,
    hidden_plaintext_proof = 8,
    plaintext_proof = 16,
	omit_cert_chain = 32
} TLSProofType;

typedef enum { 
    hash_chain_node = 1,
    plaintext_node = 2,
    merkle_hash_node = 3,
    hidden_plaintext_node = 4
} TLSProofNodeType;

// TODO: Rename
#define PROOF_SALT_SIZE (sizeof(PRUint16) + sizeof(PRUint16))
typedef struct ProofSaltStr {
	PRUint16 tree_level;
	PRUint16 salt_index;
} ProofSalt;

#define PROOF_MERKLE_NODE_SIZE (sizeof(PRUint16) + sizeof(PRUint16))
typedef struct ProofMerkleNodeStr {
	PRUint16 tree_level;
	PRUint16 chunk_index;
} ProofMerkleNode;

#endif
