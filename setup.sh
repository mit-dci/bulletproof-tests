#!/bin/bash
#git clone https://github.com/apoelstra/secp256k1-zkp
cd secp256k1-zkp
git checkout origin/2020-11--bulletproofs1-uncompressed
git checkout .
git apply ../helper.patch
./autogen.sh
./configure --enable-module-bulletproofs --enable-experimental --enable-module-generator
make -j
cd ..
