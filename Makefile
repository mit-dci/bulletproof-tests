INCDIR = secp256k1-zkp/include
LIBDIR = secp256k1-zkp/.libs
CFLAGS = -Og -ggdb -g 
LDFLAGS = -L $(LIBDIR) -I $(INCDIR) -lsecp256k1

SECPCONFFLAGS = --enable-module-bulletproofs --enable-experimental --enable-module-generator --enable-module-extrakeys --enable-module-recovery

RM = rm -rf --

.PHONY: all run lib clean debug

all: run

secp256k1-zkp:
	git clone "https://github.com/apoelstra/secp256k1-zkp"
	(cd "$@"; git checkout -b bulletproofs 'origin/2020-11--bulletproofs1-uncompressed')

lib: secp256k1-zkp
	(cd secp256k1-zkp; \
		git restore .; \
		git apply ../helper.patch; \
		./autogen.sh; \
		./configure $(SECPCONFFLAGS); \
		make -j \
	)

bin: main.c
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	$(RM) bin

debug: bin
	LD_LIBRARY_PATH=$(LIBDIR) gdb --tui ./$<

run: bin lib
	LD_LIBRARY_PATH=$(LIBDIR) ./$<

$(V).SILENT:
