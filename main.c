#include "main.h"

signed
main (void) {

    secp256k1_context * ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    proof_roundtrip(ctx);
    keyderivation_doublecheck(ctx);

    cleanup:
        secp256k1_context_destroy(ctx);
}

void
keyderivation_doublecheck (secp256k1_context * ctx) {

    unsigned char r [32] = { 0 };
    randombytes(r, sizeof r);

    unsigned long someval = randomnumber() % UINT_MAX;

    signed ret;
    secp256k1_pedersen_commitment com;
    ret = secp256k1_pedersen_commit(ctx, &com, r, someval, secp256k1_generator_h);
    assert(ret);

    unsigned char rprime [32] = { 0 };
    randombytes(rprime, sizeof rprime);

    secp256k1_pedersen_commitment aux;
    ret = secp256k1_pedersen_commit(ctx, &aux, rprime, someval, secp256k1_generator_h);
    assert(ret);

    ret = secp256k1_ec_seckey_negate(ctx, rprime);
    assert(ret);
    ret = secp256k1_ec_seckey_tweak_add(ctx, r, rprime); // r -= rprime
    assert(ret);

    secp256k1_keypair kp;
    ret = secp256k1_keypair_create(ctx, &kp, r);
    assert(ret);

    secp256k1_pubkey epk;
    ret = secp256k1_keypair_pub(ctx, &epk, &kp);
    assert(ret);

    printf("automatically-derived key from secret\n");

    unsigned char out_epk [33] = { 0 };
    size_t len = 33;
    ret = secp256k1_ec_pubkey_serialize(ctx, out_epk, &len, &epk, SECP256K1_EC_COMPRESSED);
    assert(ret);

    secp256k1_pubkey pk [2];
    secp256k1_pedersen_commitment_as_key(&com, &pk[0]);
    secp256k1_pedersen_commitment_as_key(&aux, &pk[1]);
    ret = secp256k1_ec_pubkey_negate(ctx, &pk[1]);
    assert(ret);

    const secp256k1_pubkey * pks [2];
    pks[0] = &pk[0];
    pks[1] = &pk[1];

    secp256k1_pubkey epk_check;
    ret = secp256k1_ec_pubkey_combine(ctx, &epk_check, pks, 2);
    assert(ret);

    printf("manually-derived key from commitments\n");

    unsigned char out_epkcheck [33] = { 0 };
    len = 33;
    ret = secp256k1_ec_pubkey_serialize(ctx, out_epkcheck, &len, &epk_check, SECP256K1_EC_COMPRESSED);
    assert(ret);

    for(size_t i = 0; i < 33; ++i) {
        assert(out_epk[i] == out_epkcheck[i]);
    }

    printf("manually- and automatically-drived keys match!\n");
}

void
proof_roundtrip (secp256k1_context * ctx) {

    unsigned char proof [SECP256K1_BULLETPROOFS_RANGEPROOF_UNCOMPRESSED_MAX_LENGTH_];
    size_t prooflen = SECP256K1_BULLETPROOFS_RANGEPROOF_UNCOMPRESSED_MAX_LENGTH_;

    unsigned long someval = randomnumber() % UINT_MAX;

    printf("proving that 0 <= %lu < %u\n", someval, UINT_MAX);

    secp256k1_pedersen_commitment commitment;
    signed res = prove(ctx, someval, &commitment, proof, &prooflen);
    if ( res != EXIT_SUCCESS ) {
        goto cleanup;
    }

    printf("proof created! (%zu bytes large)\nverifying proof\n", prooflen);

    res = verify(ctx, &commitment, proof, prooflen);
    if ( res != EXIT_SUCCESS ) {
        goto cleanup;
    }

    printf("verified!\n");
    cleanup:;
}

signed
prove (secp256k1_context * ctx, unsigned long value, secp256k1_pedersen_commitment * commitment, unsigned char * proof, size_t * prooflen) {

    signed status = EXIT_SUCCESS;

    // 128 == 2*n_bits (allows for proving up to 64 bits)
    secp256k1_bulletproofs_generators * gens = secp256k1_bulletproofs_generators_create(ctx, 128);
    if ( !gens ) {
        fputs("Failed to allocate bulletproofs generators\n", stderr);
        status = EXIT_FAILURE;
        goto cleanup;
    }

    unsigned char blind [32] = { 0 };
    randombytes(blind, 32);

    unsigned char nonce [32] = { 0 };
    randombytes(nonce, 32);

    signed res = secp256k1_pedersen_commit(ctx, commitment, blind, value, secp256k1_generator_h);
    if ( res != 1 ) {
        fputs("Failed to create commitment\n", stderr);
        status = EXIT_FAILURE;
        goto cleanup;
    }

    res = secp256k1_bulletproofs_rangeproof_uncompressed_prove(
        ctx,
        gens,
        secp256k1_generator_h,
        proof,
        prooflen,
        32, // n_bits
        value,
        0, // min
        commitment,
        blind,
        nonce,
        NULL, // enc_data
        NULL, // extra_commit
        0     // extra_commit length
    );

    if ( res == 0 ) {
        fputs("Failed to create proof\n", stderr);
        status = EXIT_FAILURE;
        goto cleanup;
    }

    cleanup:
        if ( gens ) { secp256k1_bulletproofs_generators_destroy(ctx, gens); }
        return status;
}

signed
verify (secp256k1_context * ctx, secp256k1_pedersen_commitment * commitment, unsigned char * proof, size_t prooflen) {

    signed status = EXIT_SUCCESS;
    
    secp256k1_scratch_space * scratch = secp256k1_scratch_space_create(ctx, 100 * 1024);

    // 128 == 2*n_bits (allows for proving up to 64 bits)
    secp256k1_bulletproofs_generators * gens = secp256k1_bulletproofs_generators_create(ctx, 128);
    if ( !gens ) {
        fputs("Failed to allocate bulletproofs generators\n", stderr);
        status = EXIT_FAILURE;
        goto cleanup;
    }

    signed res = secp256k1_bulletproofs_rangeproof_uncompressed_verify(
        ctx,
        scratch,
        gens,
        secp256k1_generator_h,
        proof,
        prooflen,
        0, // min still required (why?)
        commitment,
        NULL, // extra_commit
        0     // extra_commit length
    );

    if ( res == 0 ) {
        fputs("Failed to verify proof\n", stderr);
        status = EXIT_FAILURE;
        goto cleanup;
    }

    cleanup:
        secp256k1_scratch_space_destroy(ctx, scratch);
        if ( gens ) { secp256k1_bulletproofs_generators_destroy(ctx, gens); }
        return status;
}

signed
randombytes (void * buf, size_t bytes) {

    if ( !buf ) {
        return 0;
    }

    FILE * f = fopen("/dev/urandom", "r");
    if ( !f ) {
        return 0;
    }

    fread(buf, bytes, sizeof(unsigned char), f);
    fclose(f);
    return 1;
}

unsigned long
randomnumber() {

    unsigned long l = 0;
    assert(randombytes(&l, sizeof l));
    return l;
}

