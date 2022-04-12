INCDIR = secp256k1-zkp/include
LIBDIR = secp256k1-zkp/.libs
CFLAGS = -O0 -ggdb -g 
LDFLAGS = -L $(LIBDIR) -I $(INCDIR) -lsecp256k1

SECPCONFFLAGS = --enable-module-bulletproofs --enable-experimental --enable-module-generator

RM = rm -rf --

.PHONY: all run lib clean

all: run

secp256k1-zkp:
	git clone "https://github.com/apoelstra/secp256k1-zkp"
	(pushd "$@"; git checkout -b bulletproofs 'origin/2020-11--bulletproofs1-uncompressed')

lib: secp256k1-zkp
	(pushd secp256k1-zkp; \
		git restore .; \
		git apply ../helper.patch; \
		./autogen.sh; \
		./configure $(SECPCONFFLAGS); \
		make -j \
	)

clean:
	$(RM) bin

bin: main.c
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS)

run: bin lib
	LD_LIBRARY_PATH=$(LIBDIR) ./$^

$(V).SILENT:
