# $Id:$
# script that generates all needed word-stream names in two-byte form

(
echo "#include \"wordstreams.h\""
./stringToWchar.sh $(echo -e "0Table")
./stringToWchar.sh $(echo -e "1Table")
./stringToWchar.sh $(echo -e "Data")
./stringToWchar.sh $(echo -e "WordDocument")

./stringToWchar.sh $(echo -e "encryption")

./stringToWchar.sh $(echo -e "Root Entry")
./stringToWchar.sh $(echo -e "EncryptedPackage")
./stringToWchar.sh $(echo -e "\x06DataSpaces")
./stringToWchar.sh $(echo -e "Version")
./stringToWchar.sh $(echo -e "DataSpaceMap")
./stringToWchar.sh $(echo -e "DataSpaceInfo")
./stringToWchar.sh $(echo -e "StrongEncryptionDataSpace")
./stringToWchar.sh $(echo -e "TransformInfo")
./stringToWchar.sh $(echo -e "StrongEncryptionTransform")
./stringToWchar.sh $(echo -e "\x06Primary")
./stringToWchar.sh $(echo -e "EncryptionInfo")
) \
| sed -e 's/\x06/0x06/' \
| sed -e 's/Root Entry/RootEntry/' \
> wordstreams.c

#in Root Entry, second 'o' is a '*'  correct that
