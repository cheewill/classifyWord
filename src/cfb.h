/* $Id:$ */

#ifndef CFB_H
#define CFB_H

#include <stdint.h>
#include <stdlib.h>
#include <errno.h>

#include "byteswap.h"

typedef struct {
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
	uint32_t NumberOfDifatSectors;	// The number of DIFAT sectors
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


typedef uint32_t SECT;
#define DIFSECT    0xFFFFFFFC
#define FATSECT    0xFFFFFFFD
#define ENDOFCHAIN 0xFFFFFFFE
#define FREESECT   0xFFFFFFFF

typedef struct
{
  uint32_t  sectorCount;
  uint32_t* table;
} difat_t;


typedef struct {
  uint8_t          *data;
  uint32_t          dataSize;
  cfb_fileheader_t *fileHeader;
  difat_t           difat;
  uint32_t         *directory;
  uint32_t          directory_size;
  uint32_t         *minifat;
  uint32_t          minifat_size;
  uint8_t          *ministream;
  uint32_t          ministream_size;
} cfb_t;

void check_data_offset(cfb_t* cfb, uint32_t offset);

/* Parses the DIFAT */
void parse_difat(cfb_t *cfb);

/* Maps the contents of the file identified by the given file descriptor as data of the cfb. */
void cfb_map_data_from_file(cfb_t* cfb, int fd);

/* Unmaps the file data previously mapped by cfb_map_data_from_file. */
void cfb_unmap_data_from_file(cfb_t* cfb, int fd);

/* Parses the main structure of the cfb file format: header and fat.
   Assumes that data and dataSize is already set. */
void parse_cfb (cfb_t *cfb);

/* parse the directory */
void parse_dir (cfb_t *cfb);

/* parse the minifat */

uint32_t sector_offset (cfb_t *cfb, SECT curSect);

/* Advances the given iterator to the next block */
uint32_t iter_next_sector(cfb_t* cfb, uint32_t current_sector);

uint32_t get_fat_sector_id(difat_t* difat, uint32_t id);

uint32_t fat_next_sector(cfb_t* cfb, uint32_t fat_sector_id, uint32_t local_entry);

void debug_print_stream(cfb_t* pCfb, cfb_directoryentry_t* pDirentry);

/* Minifat related things */
void parse_minifat (cfb_t*cfb);
void load_ministream (cfb_t*cfb);
uint32_t iter_ministream_next (cfb_t*cfb, uint32_t id);

/* dump the directory entries */
void cfb_directory_dump (cfb_t * CFB);
cfb_directoryentry_t* cfb_get_direntry (cfb_t *cfb, uint32_t dir_id);
cfb_directoryentry_t* cfb_get_direntry_by_name (cfb_t *cfb, 
    uint16_t *name, uint16_t len);
#define CFB_GET_DIRENTRY_BY_NAME(cfb, name) \
  cfb_get_direntry_by_name (cfb, name, sizeof(name)/sizeof(name[0]))
#endif /* CFG_H */

