#ifndef CRYPTO_H
#define CRYPTO_H

#include "aes/aes.h"
#include "cfb.h"

#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct {
	uint8_t saltbuf[(5+16)*16];
	uint8_t ev[16];
	uint8_t evh[16];
} key_rc4basic_ctx_t;


void key_rc4basic_create(key_rc4basic_ctx_t * ctx,
                         uint8_t[16], uint8_t[16], uint8_t[16]);
void key_rc4basic_derive(uint8_t key[16], key_rc4basic_ctx_t *ctx, uint8_t pw[], size_t pwsz, uint32_t block);
bool key_rc4basic_verify(key_rc4basic_ctx_t *, uint8_t[], size_t);
void key_rc4basic_destroy(key_rc4basic_ctx_t *);
void key_rc4basic_decrypt(key_rc4basic_ctx_t *, uint8_t[], size_t, uint8_t[], size_t);

typedef struct {
	uint8_t salt[16];
	uint8_t ev[16];
	uint8_t evh[20];
	uint8_t key[16];
	size_t keysz; /* 5...16 bytes (40...128 bits) */
	size_t maxkeysz;
} key_rc4capi_ctx_t;

typedef enum
{
	unknown,
	rc4_basic,
	rc4_capi,
	aes
} crypto_algo_e;

typedef struct {
        /* values read from encryption header */
	crypto_algo_e algo;
	size_t keybits;
	size_t maxkeybits;
	uint8_t salt[16];
	size_t  salt_size;
	uint8_t ev[16];
	size_t  ev_size;
	uint8_t evh[32];
	size_t  evh_size;
        uint8_t key[32];
	/* user provided password */
	uint8_t ucs2pw[2*1000];
	size_t  ucs2pw_size;
        size_t verifier_hash_size; 
	/* the rc4 context */
	key_rc4basic_ctx_t rc4basic_ctx;
	key_rc4capi_ctx_t  rc4capi_ctx;
} crypto_ctx_t;


void key_rc4capi_create(key_rc4capi_ctx_t * ctx,
              uint8_t[16], uint8_t[16], uint8_t[16], size_t, size_t);
void key_rc4capi_derive(uint8_t key[16], key_rc4capi_ctx_t *ctx,
	                uint8_t pw[], size_t pwsz, uint32_t block);
bool key_rc4capi_verify(key_rc4capi_ctx_t *, uint8_t[], size_t);
void key_rc4capi_destroy(key_rc4capi_ctx_t *);

typedef struct {
	uint8_t salt[16];
	uint8_t ev[16];
	uint8_t evh[32];
	uint8_t key[16];
	size_t keysz; /* 5...16 bytes (40...128 bits) */
	size_t maxkeysz;
        size_t verifier_hash_size;
} key_ecma376_ctx_t;


void key_ecma376_create(crypto_ctx_t * ctx, uint8_t hash_value[20]);
void key_ecma376_derive(crypto_ctx_t *ctx, uint8_t hash_value[20], uint32_t block);
bool key_ecma376_verify(crypto_ctx_t *ctx);


typedef struct
{
	uint16_t wIdent;			// Identifier, must be 0xa5ec
	uint16_t nFib;				// Version number of the file format, should be 0x00c1
	uint16_t unused;			// Must be ignored
	uint16_t lid;				// Install language of producing app
	uint16_t pnNext;			// Offset of the FIB in the Word document
	uint16_t Flags;				// Flags A-M
	uint16_t nFibBack;			// Should be 0x00bf or 0x00c1
	uint32_t lKey;				// Size of the EncryptionHeader if fEncryption == 1 && fObfuscation == 0
} __attribute__((packed)) doc_fibbase_t;

#define FIBBASE_FLAG_ENCRYPTED		0x0100	// Flag F: fEncrypted
#define FIBBASE_FLAG_WHICHTBLSTM	0x0200	// Flag G: fWhichTblStm
#define FIBBASE_FLAG_OBFUSCATED		0x8000	// Flag M: fObfuscated

#define FIBBASE_IDENTIFIER		0xa5ec	// The Identifier which must be in the wIdent of the doc_fibbase_t structure



typedef struct
{
	uint16_t VersionMajor;			// MajorVersion of the algorithm, must be 0x0001 for RC4
	uint16_t VersionMinor;			// MinorVersion of the algorithm, must be 0x0001 for RC4
	uint8_t  Salt[16];			// The randomly generated salt value
	uint8_t  EncryptedVerifier[16];		// Additional verifier encrypted using 40-bit RC4
	uint8_t  EncryptedVerifierHash[16];	// The 40-bit RC4 MD5 hash of the verifier
} __attribute__((packed)) crypt_rc4_encryption_header_t;

#define RC4_VERSION_MAJOR	0x0001
#define RC4_VERSION_MINOR	0x0001

typedef struct
{
	uint16_t VersionMajor;			// MajorVersion of the algorithm
	uint16_t VersionMinor;			// MinorVersion of the algorithm
	uint32_t Flags;
	uint32_t HeaderSize;			// Size of the entire EncryptionHeader
} __attribute__((packed)) crypt_capi_encryption_header_t;

#define CAPI_RC4_VERSION_MAJOR2	0x0002
#define CAPI_RC4_VERSION_MAJOR3	0x0003
#define CAPI_RC4_VERSION_MINOR	0x0002
#define ENCHEADER_FLAGS_RESERVED1 0x0001
#define ENCHEADER_FLAGS_RESERVED2 0x0002
#define ENCHEADER_FLAGS_CRYPTOAPI 0x0004
#define ENCHEADER_FLAGS_DOCPROPS  0x0008
#define ENCHEADER_FLAGS_EXTERNAL  0x0010
#define ENCHEADER_FLAGS_AES       0x0020

typedef struct
{
	uint32_t Flags;				// A copy of the flags
	uint32_t SizeExtra;			// Reserved, must be 0x00000000
	uint32_t AlgID;				// Encryption Algorithm
	uint32_t AlgIDHash;			// Hashing Algorithm
	uint32_t KeySize;			// Number of bits in the encryption key
	uint32_t ProviderType;
	uint32_t Reserved1;
	uint32_t Reserved2;
	uint16_t *CSPName;                      // null-terminated unicode
} __attribute__((packed)) crypt_capi_rc4_encryption_header_t;

#define CAPI_ALGO_SEE_FLAGS	0x00000000
#define CAPI_ALGO_RC4		0x00006801
#define CAPI_ALGO_AES128	0x0000660E
#define CAPI_ALGO_AES192	0x0000660F
#define CAPI_ALGO_AES256	0x00006610

#define CAPI_ALGO_SHA1		0x00008004

#define CAPI_CSP_RC4		0x00000001
#define CAPI_CSP_AES		0x00000018


/* Returns a pointer to the fib structure */
doc_fibbase_t* getFibbase(cfb_t* pCfb);

/* Returns a pointer to the Table stream directory entry */
cfb_directoryentry_t* getTableStream(cfb_t* pCb);

/* Creates a new crypto context */
//crypto_ctx_t* create_crypto_ctx(cfb_t *pCfb);
int create_crypto_ctx(cfb_t *pCfb, crypto_ctx_t*ctx, char*pw);

/* Parses the rc4 encryption header from the given data location and 
   writes the parsed value into the given crypto_ctx_t */
void parse_rc4_encryption_header(uint8_t* pData, crypto_ctx_t* pCryptoCtx);

/* Parses the crypto api rc4 encryption header from the given data location and 
   writes the parsed value into the given crypto_ctx_t */
void parse_capi_encryption_header(uint8_t* pData, crypto_ctx_t* pCryptoCtx);

void decrypt_word_file(cfb_t *pCfb, crypto_ctx_t* pCryptoCtx);

#endif
