/* $Id: parse.h 204 2008-08-22 11:40:20Z rkeller $ */

#ifndef PARSE_H
#define PARSE_H

#include <fpwchk/word.h>

#include <stdint.h>
#include <stdlib.h>

#include "byteswap.h"

typedef struct
{
	uint8_t  HeaderSignature[8];		// The identifcation for CFB
	uint8_t  HeaderCLSID[16];		// Reserved, must be all 0x00
	uint16_t MinorVersion;			// Should be 0x003e
	uint16_t MajorVersion;			// Should be 0x0003 or 0x0004
	uint16_t ByteOrder;			// Must be 0xfffe
	uint16_t SectorShift;			// Size of a sector as a power of 2
	uint16_t MiniSectorShift;		// Must be 0x0006
	uint8_t  Reserved[6];			// Reserved, must be all 0x00
	uint32_t NumberOfDirectorySectors;	// The number of directory sectors or 0 if MajorVersion == 3
	uint32_t NumberOfFatSectors;		// The number of FAT sectors in this compound file
	uint32_t FirstDirectorySectorLocation;	// The ID of the first sector of the directory
	uint32_t TransactionSignatureNumber;	// Sequence number of last file transaction
	uint32_t MiniStreamCutoffSize;		// Must be set to 0x00001000
	uint32_t FirstMiniFatSectorLocation;	// The ID of the first mini FAT sector
	uint32_t NumberOfMiniFatSectors;	// The number of the mini FAT sectors
	uint32_t FirstDifatSectorLocation;	// The ID of the first DIFAT sector
	uint32_t NumberOfDifatSectors;		// The number of DIFAT sectors
	uint32_t Difat[109];			// The first 109 FAT sector locations
} __attribute__((packed)) cfb_fileheader_t;	// 512 bytes for the Compound File Header

#define CFB_FILEHEADER_BYTEORDER_LE	0xFFFE
#define CFB_FILEHEADER_BYTEORDER_BE	0xFEFF

typedef struct
{
	uint16_t DirectoryEntryName[32];	// Directory Entry Name as UTF-16
	uint16_t DirectoryEntryNameLength;	// Length of the DirectoryEntryName in bytes
	uint8_t  ObjectType;			// Stream = 0x02
	uint8_t  ColorFlag;			// red = 0x00, black = 0x01
	uint32_t LeftSiblingId;			// Stream ID of the left sibling
	uint32_t RightSiblingId;		// Stream ID of the right sibling
	uint32_t ChildId;			// Stream ID of a child
	uint8_t  CLSID[16];			// Class GUID of the entry
	uint32_t StateBits;			// User-defined flags for storage or root
	uint64_t CreationTime;			// Creation time of storage object
	uint64_t ModifiedTime;			// Modified time of storage object
	uint32_t StartingSectorLocation;	// The ID of the first sector for this storage object
	uint32_t StreamSizeLow;			// The low 32 bits of the size of the storage object stream
	uint32_t StreamSizeHigh;		// The high 32 bits of the size of the storage object stream
} __attribute__((packed)) cfb_directoryentry_t;	// 128 bytes per directory entry

#define CFB_DIRECTORYENTRY_OBJECTTYPE_UNKNOWN	0x00
#define CFB_DIRECTORYENTRY_OBJECTTYPE_STORAGE	0x01
#define CFB_DIRECTORYENTRY_OBJECTTYPE_STREAM	0x02
#define CFB_DIRECTORYENTRY_OBJECTTYPE_ROOT	0x05

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
#define CAPI_RC4_VERSION_MAJOR3	0x0002
#define CAPI_RC4_VERSION_MINOR	0x0002


#define CAPI_ALGO_SEE_FLAGS	0x00000000
#define CAPI_ALGO_RC4		0x00006801
#define CAPI_ALGO_AES128	0x0000660E
#define CAPI_ALGO_AES192	0x0000660F
#define CAPI_ALGO_AES256	0x00006610

#define CAPI_ALGO_SHA1		0x00008004

#define CAPI_CSP_RC4		0x00000001
#define CAPI_CSP_AES		0x00000018

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
	uint16_t CSPName;
} __attribute__((packed)) crypt_capi_rc4_encryption_header_t;

typedef struct
{
	uint8_t *pSalt;
	size_t   cbSalt;
	uint8_t *pEncryptedVerifier;
	size_t   cbEncryptedVerifier;
	uint8_t *pEncryptedVerifierHash;
	size_t   cbEncryptedVerifierHash;
} crypto_data_t;

typedef enum
{
	unknown,
	rc4_basic,
	rc4_capi,
} crypto_algo_e;

typedef struct
{
	uint32_t  sectorCount;
	uint32_t* table;
} difat_t;

typedef struct 
{
	uint32_t size;
	uint32_t firstSector;
} stream_info_t;

typedef struct {
	stream_info_t *tableStream;
	stream_info_t *documentStream;
	stream_info_t *dataStream;
} word_file_streams_t;

crypto_algo_e parse_word_headers(FILE *file, size_t *pKeySize, size_t *pMaxKeySize,
			uint8_t *pSalt, size_t cbSalt,
			uint8_t *pEncryptedVerifier, size_t cbEncryptedVerifier,
			uint8_t *pEncryptedVerifierHash, size_t cbEncryptedVerifierHash);
			
/* Parses a directory entry in the CFB storage. */
int parse_directory_entry(FILE *file, difat_t* difat, word_file_streams_t* streams, uint32_t ulSectorOffset, uint16_t sectorShift, uint32_t entryId,
			  crypto_data_t *pData, crypto_algo_e *pAlgo, size_t *pKeySize, size_t *pMaxKeySize, int *whichTable);

/* Checks of two directory entry names are the same. */
int is_same_name(const uint16_t *name1, size_t size1, const uint16_t *name2, size_t size2);

/* Parses the FIBBase header from the WordDocument stream. */
int parse_fibbase(FILE *file, doc_fibbase_t **ppFibBase);

/* RC4 (non Crypto API) header parsing function. */
void parse_rc4_encryption_header(crypt_rc4_encryption_header_t *pHeader, crypto_data_t *pData);

/* Crypto API header parsing function. */
int parse_capi_encryption_header(crypt_capi_encryption_header_t *pHeader, crypto_data_t *pData,
					  FILE *file, uint32_t ulStreamBase, size_t *pKeySize, size_t *pMaxKeySize);

#define SECTOR_OFFSET(sectorId, sectorShift)	((sectorId + 1) << sectorShift)

#endif /* PARSE_H */
