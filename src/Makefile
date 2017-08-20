# $Id: Makefile  WK 2009 Allemann $

OPENSSL_LIB = /usr/local/lib
OPENSSL_INC = /usr/local/include

LIBS = -lcrypto
LDFLAGS += -L$(OPENSSL_LIB)
CPPFLAGS += -I$(OPENSSL_INC) -I../include -g3 -DDEBUG
# -march=native -fomit-frame-pointer -funroll-loops
CFLAGS := -O2 -funroll-loops $(CFLAGS)
#CFLAGS += -fPIC
CFLAGS += -std=c99 -Wall -pedantic-errors -DDEBUG 

# Uncomment this for systems without wcsdup(3), which includes
# MacOS X 10.3, FreeBSD 6.0, NetBSD 3.0, OpenBSD 3.8, AIX 4.3.2,
# HP-UX 11, IRIX 6.5, OSF/1 5.1, Solaris 10, Cygwin and BeOS
#CPPFLAGS += -DCOMPAT_WCSDUP

OBJS = strconv.o parse.o cfb.o
OBJS_CLASSIFY = cfb.o strconv.o crypto.o wordstreams.o aes/aeskey.o aes/aescrypt.o aes/aestab.o
TARGETS = classify
#TARGETS += libfpwchk-word.so libfpwchk-word.a

STRIP ?= strip

all: $(TARGETS) 
#dotest



classify: $(OBJS_CLASSIFY) classify.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)


clean:
	rm -f *.o aes/*.o *~ *.core $(TARGETS)

.PHONY: all clean dotest strip

