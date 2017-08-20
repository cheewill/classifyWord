#!/bin/bash

STRING=$1
echo "uint16_t cfb_direntry_$STRING[] = { "
echo -n $STRING | hexdump -e '/1 " htoles(0x00%02x), \n" '
echo " htoles(0x0000) }; /* $STRING */ "
