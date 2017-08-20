/* $Id:$ */

#include "cfb.h"
#include "strconv.h"
#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <string.h>  
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "errorcodes.h"
#include "debug.h"
#include "crypto.h"
#include "key.h"

#include "wordstreams.h"

// return true, if password is ok

bool verify_password(crypto_ctx_t* pCryptoCtx) {
  //DPRINTF ("switch on [crypto algo=%d]\n", pCryptoCtx->algo);
  switch(pCryptoCtx->algo) {
    case rc4_basic: {
      key_rc4basic_create(&pCryptoCtx->rc4basic_ctx,
	      pCryptoCtx->salt, pCryptoCtx->ev, pCryptoCtx->evh);
      int result = key_rc4basic_verify(&pCryptoCtx->rc4basic_ctx,
                  pCryptoCtx->ucs2pw, pCryptoCtx->ucs2pw_size);
      return result;
    }
    break;
    case rc4_capi: {
      key_rc4capi_create( &pCryptoCtx->rc4capi_ctx,
	               pCryptoCtx->salt, 
	                       pCryptoCtx->ev, pCryptoCtx->evh,
	                       pCryptoCtx->keybits, pCryptoCtx->maxkeybits);
      int result = key_rc4capi_verify ( &pCryptoCtx->rc4capi_ctx,
                  pCryptoCtx->ucs2pw, pCryptoCtx->ucs2pw_size);
      return result;
    }
    break;
    case aes: {
      return key_ecma376_verify(pCryptoCtx);
    }
    break;
    default:
      fprintf (stderr, "unknown encryption algorithm [%d]\n", 
               pCryptoCtx->algo);
      exit(UNKOWN_ENCRYPTION_ALGORITHM);
  }
}

void write_word2007_stream_to_file(FILE* file, cfb_t* pCfb, cfb_directoryentry_t* pDirentry) {
  int sectorSize = 1 << htoles(pCfb->fileHeader->SectorShift);
  int currentSector = htoles(pDirentry->StartingSectorLocation);
  
  uint8_t* data = &pCfb->data[sector_offset(pCfb, currentSector)];
  int64_t remaining = pDirentry->StreamSizeLow;
  DPRINTF("Word2007 Stream Content size = %d\n", remaining);
  
  int skipBytes = 8; // first 8 bytes encode the length
  
  size_t written = fwrite(data+sizeof(uint32_t), 1, sectorSize - skipBytes, file);
  DPRINTF("written = %d\n", written);
  assert(written == sectorSize - skipBytes);
  HD("First Sector", data+skipBytes, sectorSize - skipBytes);
  
  remaining -= sectorSize;
  
  while(remaining > 0) {
    currentSector = iter_next_sector(pCfb, currentSector);
    if (currentSector == ENDOFCHAIN) {
    	fprintf(stderr, "Reached end of chain but %d bytes remaining\n", remaining);
	exit(INVALID_DOCUMENT_STRUCTURE);
    }
    if (currentSector == FREESECT) {
    	fprintf(stderr, "Oops, free sector in stream\n");
	exit(INVALID_DOCUMENT_STRUCTURE);
    }
  
    data = &pCfb->data[sector_offset(pCfb, currentSector)];    
    uint32_t bytes_to_write = remaining < sectorSize ? remaining : sectorSize;
    size_t written = fwrite(data, 1, bytes_to_write, file);
    assert(written == bytes_to_write);
  
    HD("", data, bytes_to_write);
    DPRINTF("2remaining = %d\n",remaining);
    remaining -= sectorSize;
  }
  
  fseek(file, 0, SEEK_SET);
  
  
  
  
}

void write_cfb_to_file(FILE* file, cfb_t* cfb) {
  fwrite(cfb->data, cfb->dataSize, 1, file);
}

int main (int argc, char**argv) {
  if (argc != 3) {
     fprintf(stderr, "usage: decrypt file.doc password\n");
     exit(INVALID_ARGUMENTS);
  }

  int fd;

  printf ("opening file %s\n", argv[1]);
  if ((fd = open(argv[1], O_RDONLY)) == -1) {
    fprintf(stderr, "open(\"%s\", O_RDONLY) => %s\n",
		    argv[1], strerror(errno));
    exit(FILE_OPEN_FAILED);
  }
  
  printf ("parsing  cfb\n");
  cfb_t CFB;
  cfb_map_data_from_file(&CFB, fd);
  parse_cfb(&CFB);
  printf ("\t\t\tdone \n");

  cfb_directory_dump (&CFB);

  // find the necessary crypto information fields
  //
  /*debug_print_stream (&CFB, CFB_GET_DIRENTRY_BY_NAME (&CFB, 
                              cfb_direntry_Version));
  debug_print_stream (&CFB, CFB_GET_DIRENTRY_BY_NAME (&CFB, 
                              cfb_direntry_DataSpaceMap));
  debug_print_stream (&CFB, CFB_GET_DIRENTRY_BY_NAME (&CFB, 
                              cfb_direntry_StrongEncryptionDataSpace));
  debug_print_stream (&CFB, CFB_GET_DIRENTRY_BY_NAME (&CFB, 
                              cfb_direntry_0x06Primary));
  debug_print_stream (&CFB, CFB_GET_DIRENTRY_BY_NAME (&CFB, 
                              cfb_direntry_EncryptionInfo));
			      */
  /*    
  cfb_directoryentry_t *pWordDocDirentry = CFB_GET_DIRENTRY_BY_NAME (&CFB, 
        cfb_direntry_encryption);
  if (pWordDocDirentry!=0) {
    printf ("WordDocument Stream Data:\n");
    debug_print_stream(&CFB, pWordDocDirentry);
  }
  */
 
  crypto_ctx_t CryptoCtx; 
  if (create_crypto_ctx (&CFB, &CryptoCtx, argv[2]) != 0) {
    fprintf (stderr, "Cannot create crypto context\n");
    exit(FILE_NOT_ENCRYPTED);
  }

  if (!verify_password(&CryptoCtx)) {
    fprintf(stderr, "Invalid password!\n");
    exit(INVALID_PASSWORD);
  }
  DPRINTF("Password matches!\n");
  
  decrypt_word_file(&CFB, &CryptoCtx);
  
  int name_length = strlen(argv[1]);
  char *ending = ".decrypted";
  char buf[name_length + strlen(ending) + 1];
  memcpy(&buf[0], argv[1], name_length);
  memcpy(&buf[name_length], ending, strlen(ending));
  buf[name_length + strlen(ending)] = 0;
  
  DPRINTF("Write decrypted document to %s\n", buf);
  
  FILE* newfile = fopen(buf, "w");
  
  switch(CryptoCtx.algo) {
    case rc4_basic:
    case rc4_capi:
      write_cfb_to_file(newfile, &CFB);
      break;
    case aes: 
      write_word2007_stream_to_file(newfile, &CFB, CFB_GET_DIRENTRY_BY_NAME (&CFB, cfb_direntry_EncryptedPackage));
      break;
    case unknown:
      exit(UNKOWN_ENCRYPTION_ALGORITHM);
  }

  fclose(newfile);

  cfb_unmap_data_from_file(&CFB, fd);
  int error = close(fd);
  if (error) {
    DPRINTF("Failed to close file\n");
  }
  
  return 0;
}
