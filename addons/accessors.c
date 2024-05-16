#include "oqs/oqs.h"

//Accessor functions for the OQS_KEM struct

const char *OQS_KEM_get_method_name(const OQS_KEM *kem) {
    return kem->method_name;
}

const char *OQS_KEM_get_alg_version(const OQS_KEM *kem) {
    return kem->alg_version;
}

bool OQS_KEM_get_ind_cca(const OQS_KEM *kem) {
    return kem->ind_cca;
}

size_t OQS_KEM_get_length_public_key(const OQS_KEM *kem) {
    return kem->length_public_key;
}

size_t OQS_KEM_get_length_secret_key(const OQS_KEM *kem) {
    return kem->length_secret_key;
}

size_t OQS_KEM_get_length_ciphertext(const OQS_KEM *kem) {
    return kem->length_ciphertext;
}

size_t OQS_KEM_get_length_shared_secret(const OQS_KEM *kem) {
    return kem->length_shared_secret;
}

//Accessor functions for the OQS_SIG struct

const char *OQS_SIG_get_method_name(const OQS_SIG *sig) {
    return sig->method_name;
}

const char *OQS_SIG_get_alg_version(const OQS_SIG *sig) {
    return sig->alg_version;
}

bool OQS_SIG_get_euf_cma(const OQS_SIG *sig) {
    return sig->euf_cma;
}

size_t OQS_SIG_get_length_public_key(const OQS_SIG *sig) {
    return sig->length_public_key;
}

size_t OQS_SIG_get_length_secret_key(const OQS_SIG *sig) {
    return sig->length_secret_key;
}

size_t OQS_SIG_get_length_signature(const OQS_SIG *sig) {
    return sig->length_signature;
}
