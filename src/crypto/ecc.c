#include <assert.h>
#include <stdint.h>
#include <string.h>

#include <secp256k1/include/secp256k1.h>
#include <secp256k1/include/secp256k1_recovery.h>

#include <dogecoin/crypto/random.h>
#include <dogecoin/dogecoin.h>

/* This is a global variable that is used to store the secp256k1 context. */
static secp256k1_context* secp256k1_ctx = NULL;

/**
 * The function starts the ECC library by initializing a random number generator and then initializing
 * the secp256k1 library
 * 
 * @return Nothing.
 */
dogecoin_bool dogecoin_ecc_start(void)
{
    dogecoin_random_init();
    secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (secp256k1_ctx == NULL)
        return false;
    uint8_t seed[32];
    int ret;
    ret = dogecoin_random_bytes(seed, 32, 0);
    if (!ret)
        return false;
    ret = secp256k1_context_randomize(secp256k1_ctx, seed);
    if (!ret)
        return false;
    return true;
}

/**
 * It stops the secp256k1 library from being used.
 */
void dogecoin_ecc_stop(void)
{
    secp256k1_context* ctx = secp256k1_ctx;
    secp256k1_ctx = NULL;
    if (ctx)
        secp256k1_context_destroy(ctx);
}

/**
 * Given a private key, it will return the corresponding public key
 * 
 * @param private_key The private key to generate the public key from.
 * @param public_key The public key will be returned here. Must be 65 bytes or 33 bytes, depending on
 * whether you want the compressed or uncompressed version.
 * @param in_outlen The length of the input buffer.
 * @param compressed Whether or not the public key should be compressed.
 * 
 * @return Nothing.
 */
void dogecoin_ecc_get_pubkey(const uint8_t* private_key, uint8_t* public_key, size_t* in_outlen, dogecoin_bool compressed)
{
    secp256k1_pubkey pubkey;
    assert(secp256k1_ctx);
    assert((int)*in_outlen == (compressed ? 33 : 65));
    memset(public_key, 0, *in_outlen);
    if (!secp256k1_ec_pubkey_create(secp256k1_ctx, &pubkey, (const unsigned char*)private_key))
        return;
    if (!secp256k1_ec_pubkey_serialize(secp256k1_ctx, public_key, in_outlen, &pubkey, compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED))
        return;
    return;
}

/**
 * It takes a private key and a tweak and returns a bool
 * 
 * @param private_key The private key to be tweaked.
 * @param tweak The tweak to be added to the private key.
 * 
 * @return The return value is a boolean value indicating whether the tweak was successful.
 */
dogecoin_bool dogecoin_ecc_private_key_tweak_add(uint8_t* private_key, const uint8_t* tweak)
{
    assert(secp256k1_ctx);
    return secp256k1_ec_privkey_tweak_add(secp256k1_ctx, (unsigned char*)private_key, (const unsigned char*)tweak);
}

/**
 * The function takes a public key and a tweak and adds the tweak to the public key
 * 
 * @param public_key_inout The public key to be tweaked.
 * @param tweak The tweak is a 32-byte array.
 * 
 * @return Nothing.
 */
dogecoin_bool dogecoin_ecc_public_key_tweak_add(uint8_t* public_key_inout, const uint8_t* tweak)
{
    size_t out = DOGECOIN_ECKEY_COMPRESSED_LENGTH;
    secp256k1_pubkey pubkey;
    assert(secp256k1_ctx);
    if (!secp256k1_ec_pubkey_parse(secp256k1_ctx, &pubkey, public_key_inout, 33))
        return false;
    if (!secp256k1_ec_pubkey_tweak_add(secp256k1_ctx, &pubkey, (const unsigned char*)tweak))
        return false;
    if (!secp256k1_ec_pubkey_serialize(secp256k1_ctx, public_key_inout, &out, &pubkey, SECP256K1_EC_COMPRESSED))
        return false;
    return true;
}

/**
 * Verify that the private key is valid.
 * 
 * @param private_key The private key to be verified.
 * 
 * @return A boolean value.
 */
dogecoin_bool dogecoin_ecc_verify_privatekey(const uint8_t* private_key)
{
    assert(secp256k1_ctx);
    return secp256k1_ec_seckey_verify(secp256k1_ctx, (const unsigned char*)private_key);
}

/**
 * The function takes a public key and checks if it is valid
 * 
 * @param public_key The public key bytes.
 * @param compressed Whether or not the public key is compressed.
 * 
 * @return A boolean value.
 */
dogecoin_bool dogecoin_ecc_verify_pubkey(const uint8_t* public_key, dogecoin_bool compressed)
{
    secp256k1_pubkey pubkey;
    assert(secp256k1_ctx);
    if (!secp256k1_ec_pubkey_parse(secp256k1_ctx, &pubkey, public_key, compressed ? 33 : 65)) {
        memset(&pubkey, 0, sizeof(pubkey));
        return false;
    }
    memset(&pubkey, 0, sizeof(pubkey));
    return true;
}

/**
 * Given a private key, a hash of a message, and a nonce function, 
 * sign the hash of the message with the private key and return the signature
 * 
 * @param private_key The private key to sign with.
 * @param hash The hash of the message to be signed.
 * @param sigder The output buffer to write the DER-encoded signature to.
 * @param outlen The length of the output buffer.
 * 
 * @return 1 if the signature is valid, 0 otherwise.
 */
dogecoin_bool dogecoin_ecc_sign(const uint8_t* private_key, const uint256 hash, unsigned char* sigder, size_t* outlen)
{
    assert(secp256k1_ctx);
    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ecdsa_sign(secp256k1_ctx, &sig, hash, private_key, secp256k1_nonce_function_rfc6979, NULL))
        return 0;
    if (!secp256k1_ecdsa_signature_serialize_der(secp256k1_ctx, sigder, outlen, &sig))
        return 0;
    return 1;
}

/**
 * It takes a private key, a hash, and a nonce function, and returns a signature
 * 
 * @param private_key The private key to sign with.
 * @param hash The hash of the message to be signed.
 * @param sigcomp The output buffer to write the signature to.
 * @param outlen The length of the output signature.
 * 
 * @return Nothing.
 */
dogecoin_bool dogecoin_ecc_sign_compact(const uint8_t* private_key, const uint256 hash, unsigned char* sigcomp, size_t* outlen)
{
    assert(secp256k1_ctx);
    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ecdsa_sign(secp256k1_ctx, &sig, hash, private_key, secp256k1_nonce_function_rfc6979, NULL))
        return 0;
    *outlen = 64;
    if (!secp256k1_ecdsa_signature_serialize_compact(secp256k1_ctx, sigcomp, &sig))
        return 0;
    return 1;
}

/**
 * It takes a private key, a hash, and a nonce function, and returns a signature
 * 
 * @param private_key The private key to sign with.
 * @param hash The hash of the message to sign.
 * @param sigrec A pointer to a 65-byte array where the signature will be placed.
 * @param outlen The length of the output signature.
 * @param recid The recovery id.
 * 
 * @return 1 if the signature is valid, 0 otherwise.
 */
dogecoin_bool dogecoin_ecc_sign_compact_recoverable(const uint8_t* private_key, const uint256 hash, unsigned char* sigrec, size_t* outlen, int* recid)
{
    assert(secp256k1_ctx);
    secp256k1_ecdsa_recoverable_signature sig;
    if (!secp256k1_ecdsa_sign_recoverable(secp256k1_ctx, &sig, hash, private_key, secp256k1_nonce_function_rfc6979, NULL))
        return 0;
    *outlen = 65;
    if (!secp256k1_ecdsa_recoverable_signature_serialize_compact(secp256k1_ctx, sigrec, recid, &sig))
        return 0;
    return 1;
}

/**
 * Given a signature and hash, recover the public key
 * 
 * @param sigrec the signature
 * @param hash The hash of the message that was signed.
 * @param recid The recovery id.
 * @param public_key The public key will be returned here. Must be preallocated.
 * @param outlen The length of the output buffer.
 * 
 * @return A boolean value.
 */
dogecoin_bool dogecoin_ecc_recover_pubkey(const unsigned char* sigrec, const uint256 hash, const int recid, uint8_t* public_key, size_t* outlen)
{
    assert(secp256k1_ctx);
    secp256k1_pubkey pubkey;
    secp256k1_ecdsa_recoverable_signature sig;
    if (!secp256k1_ecdsa_recoverable_signature_parse_compact(secp256k1_ctx, &sig, sigrec, recid))
        return false;
    if (!secp256k1_ecdsa_recover(secp256k1_ctx, &pubkey, &sig, hash))
        return 0;
    if (!secp256k1_ec_pubkey_serialize(secp256k1_ctx, public_key, outlen, &pubkey, SECP256K1_EC_COMPRESSED))
        return 0;
    return 1;
}

/**
 * The function takes a public key, a boolean indicating whether the public key is compressed, a hash,
 * and a signature. It returns a boolean indicating whether the signature is valid for the given public
 * key and hash
 * 
 * @param public_key The public key bytes.
 * @param compressed Whether or not the public key is compressed.
 * @param hash The hash of the message to be signed.
 * @param sigder The DER-encoded signature.
 * @param siglen The length of the signature.
 * 
 * @return A boolean value.
 */
dogecoin_bool dogecoin_ecc_verify_sig(const uint8_t* public_key, dogecoin_bool compressed, const uint256 hash, unsigned char* sigder, size_t siglen)
{
    assert(secp256k1_ctx);
    secp256k1_ecdsa_signature sig;
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_parse(secp256k1_ctx, &pubkey, public_key, compressed ? 33 : 65))
        return false;
    if (!secp256k1_ecdsa_signature_parse_der(secp256k1_ctx, &sig, sigder, siglen))
        return false;
    return secp256k1_ecdsa_verify(secp256k1_ctx, &sig, hash, &pubkey);
}

/**
 * The ECDSA signature is converted from compact to DER format
 * 
 * @param sigcomp_in The signature to be normalized.
 * @param sigder_out The output buffer to write the der-encoded signature to.
 * @param sigder_len_out The length of the output signature.
 * 
 * @return true if the signature is valid, and false otherwise.
 */
dogecoin_bool dogecoin_ecc_compact_to_der_normalized(unsigned char* sigcomp_in, unsigned char* sigder_out, size_t* sigder_len_out)
{
    assert(secp256k1_ctx);
    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ecdsa_signature_parse_compact(secp256k1_ctx, &sig, sigcomp_in))
        return false;
    secp256k1_ecdsa_signature sigNorm;
    secp256k1_ecdsa_signature_normalize(secp256k1_ctx, &sigNorm, &sig);
    return secp256k1_ecdsa_signature_serialize_der(secp256k1_ctx, sigder_out, sigder_len_out, &sigNorm);
}

/**
 * Convert a DER-encoded signature to a compact signature
 * 
 * @param sigder_in The DER-encoded signature.
 * @param sigder_len The length of the DER encoded signature.
 * @param sigcomp_out The output buffer to write the serialized signature to.
 * 
 * @return true if the signature is valid, and false otherwise.
 */
dogecoin_bool dogecoin_ecc_der_to_compact(unsigned char* sigder_in, size_t sigder_len, unsigned char* sigcomp_out)
{
    assert(secp256k1_ctx);
    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ecdsa_signature_parse_der(secp256k1_ctx, &sig, sigder_in, sigder_len))
        return false;
    return secp256k1_ecdsa_signature_serialize_compact(secp256k1_ctx, sigcomp_out, &sig);
}
