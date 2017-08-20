#include "cfb.h"
#include "strconv.h"
#include <stdio.h>
#include <errno.h>
#include <string.h>  
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "errorcodes.h"
#include "crypto.h"

//--- MAIN ---

int main (int argc, char**argv) {
  if (argc != 2) {
     fprintf(stderr, "usage: ./classify M$Wordfile.doc \n");
     exit(INVALID_ARGUMENTS);
  }

  int fd;

  //Opening File
  printf ("opening file %s\n\n", argv[1]);
  if ((fd = open(argv[1], O_RDONLY)) == -1) {
    fprintf(stderr, "open(\"%s\", O_RDONLY) => %s\n",
		    argv[1], strerror(errno));
    exit(FILE_OPEN_FAILED);
  }
  
  //Parsing CFB
  cfb_t CFB;
  cfb_map_data_from_file(&CFB, fd);
  parse_cfb(&CFB);
  
  //Dump CFB Directory
  cfb_directory_dump (&CFB);
 
  //Create Crypto-Context
  crypto_ctx_t CryptoCtx; 
  create_crypto_ctx (&CFB, &CryptoCtx, "");
  
  cfb_unmap_data_from_file(&CFB, fd);
  int error = close(fd);
  if (error) {
    printf("Failed to close file\n");
  }
  
  return 0;
}
