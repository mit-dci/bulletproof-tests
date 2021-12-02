INCDIR = ../../bulletproofs/elements/include
LIBDIR = ../../bulletproofs/elements/.libs
CFLAGS = -O0 -ggdb -g 
LDFLAGS = -L $(LIBDIR) -I $(INCDIR) -lsecp256k1

RM = rm -rf --

.PHONY: all run clean

all: run

clean:
	$(RM) bin

bin: secp_test.c
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS)

run: bin
	LD_LIBRARY_PATH=$(LIBDIR) ./$^

$(V).SILENT:
