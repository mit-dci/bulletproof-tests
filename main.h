#ifndef MAIN_H
#define MAIN_H

#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <assert.h>

#include "secp256k1.h"
#include "secp256k1_bulletproofs.h"

signed
randombytes (void *, size_t);

unsigned long
randomnumber (void);

signed
prove (secp256k1_context *, unsigned long, secp256k1_pedersen_commitment *, unsigned char *, size_t *);

signed
verify (secp256k1_context *, secp256k1_pedersen_commitment *, unsigned char *, size_t);

void
proof_roundtrip (secp256k1_context *);

#endif
