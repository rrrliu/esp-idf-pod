#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "esp_system.h"
#include "mbedtls/base64.h"
#include "mbedtls/sha256.h"
#include "esp_random.h"
#include "poseidon_constants.h"


#define P 21888242871839275222246405745257275088548364400416034343698204186575808495617ULL
#define Order 21888242871839275222246405745257275088614511777268538073601725287587578984328ULL
#define SubOrder (Order >> 3)
#define BjA 168700
#define BjD 168696

typedef struct {
    uint64_t x;
    uint64_t y;
} Point;

Point Base8 = {5299619240641551281634865583518297030282874472190772894086521144482721001553ULL,
               16950150798460657717958625567821834550301663161624707787222815936182638968203ULL};

uint64_t mod_p(uint64_t x) {
    return x % P;
}

uint64_t inv(uint64_t a, uint64_t n) {
    int64_t t = 0, newt = 1;
    uint64_t r = n, newr = a;

    while (newr != 0) {
        uint64_t quotient = r / newr;
        int64_t temp_t = newt;
        newt = t - quotient * newt;
        t = temp_t;
        uint64_t temp_r = newr;
        newr = r - quotient * newr;
        r = temp_r;
    }

    if (r > 1) return 0;
    if (t < 0) t += n;

    return t;
}

uint64_t pow_mod_p(uint64_t base, int exp) {
    uint64_t result = 1;
    base = mod_p(base);
    while (exp > 0) {
        if (exp & 1)
            result = mod_p(result * base);
        base = mod_p(base * base);
        exp >>= 1;
    }
    return result;
}

uint64_t poseidon(uint64_t* inputs, int input_len) {
    int t = input_len + 1;
    uint64_t state[t];
    memset(state, 0, sizeof(state));
    memcpy(state + 1, inputs, input_len * sizeof(uint64_t));

    for (int r = 0; r < 8 + N_ROUNDS_P[t-2]; r++) {
        for (int i = 0; i < t; i++) {
            state[i] = mod_p(state[i] + POSEIDON_C[t-2][r*t + i]);
        }

        if (r < 4 || r >= 4 + N_ROUNDS_P[t-2]) {
            for (int i = 0; i < t; i++) {
                state[i] = pow_mod_p(state[i], 5);
            }
        } else {
            state[0] = pow_mod_p(state[0], 5);
        }

        uint64_t new_state[t];
        for (int i = 0; i < t; i++) {
            new_state[i] = 0;
            for (int j = 0; j < t; j++) {
                new_state[i] = mod_p(new_state[i] + mod_p(POSEIDON_C[t-2][t*t + i*t + j] * state[j]));
            }
        }
        memcpy(state, new_state, sizeof(state));
    }

    return mod_p(state[0]);
}

Point add_bj(Point p1, Point p2) {
    Point result;
    uint64_t x1 = p1.x, y1 = p1.y, x2 = p2.x, y2 = p2.y;
    uint64_t denom1 = mod_p(1 + BjD * mod_p(mod_p(x1 * x2) * mod_p(y1 * y2)));
    uint64_t denom2 = mod_p(1 - BjD * mod_p(mod_p(x1 * x2) * mod_p(y1 * y2)));
    result.x = mod_p(mod_p(x1 * y2 + y1 * x2) * inv(denom1, P));
    result.y = mod_p(mod_p(y1 * y2 - BjA * mod_p(x1 * x2)) * inv(denom2, P));
    return result;
}

Point multiply_bj(Point pt, uint64_t n) {
    Point result = {0, 1};
    Point base = pt;
    while (n > 0) {
        if (n & 1)
            result = add_bj(result, base);
        base = add_bj(base, base);
        n >>= 1;
    }
    return result;
}

void blake512(const uint8_t* input, size_t input_len, uint8_t* output) {
    // Placeholder for BLAKE-512 implementation
    // In a real implementation, you would use a cryptographic library
    memset(output, 0, 64);
}

typedef struct {
    uint8_t publicKey[32];
    uint8_t signature[64];
} EdDSASignature;

EdDSASignature eddsa_poseidon_sign(const uint8_t* privateKey, uint64_t message) {
    EdDSASignature result;
    uint8_t sBuff[64];
    blake512(privateKey, 32, sBuff);
    
    sBuff[0] &= 0xF8;
    sBuff[31] &= 0x7F;
    sBuff[31] |= 0x40;

    uint64_t s = 0;
    for (int i = 0; i < 32; i++) {
        s |= ((uint64_t)sBuff[i]) << (8 * i);
    }

    Point A = multiply_bj(Base8, s >> 3);

    uint8_t message_bytes[32];
    for (int i = 0; i < 32; i++) {
        message_bytes[i] = (message >> (8 * i)) & 0xFF;
    }

    uint8_t rBuff[64];
    blake512(sBuff + 32, 64, rBuff);
    uint64_t r = 0;
    for (int i = 0; i < 32; i++) {
        r |= ((uint64_t)rBuff[i]) << (8 * i);
    }
    r %= SubOrder;

    Point R8 = multiply_bj(Base8, r);
    uint64_t hms = poseidon((uint64_t[]){R8.x, R8.y, A.x, A.y, message}, 5);
    uint64_t S = (r + hms * s) % SubOrder;

    // Pack the public key
    uint64_t pm1d2 = mod_p((P - 1) * inv(2, P));
    memcpy(result.publicKey, &A.y, 32);
    if (A.x > pm1d2) result.publicKey[31] |= 0x80;

    // Pack the signature
    memcpy(result.signature, &R8.y, 32);
    if (R8.x > pm1d2) result.signature[31] |= 0x80;
    memcpy(result.signature + 32, &S, 32);

    return result;
}

uint64_t leanIMT(uint64_t* items, size_t item_count) {
    while (item_count > 1) {
        for (size_t i = 0; i < item_count; i += 2) {
            if (i + 1 < item_count) {
                items[i / 2] = poseidon((uint64_t[]){items[i], items[i + 1]}, 2);
            } else {
                items[i / 2] = items[i];
            }
        }
        item_count = (item_count + 1) / 2;
    }
    return items[0];
}

uint64_t pod_hash(const char* key, const char* value, const char* type) {
    if (strcmp(type, "string") == 0) {
        uint8_t hash[32];
        mbedtls_sha256((uint8_t*)value, strlen(value), hash, 0);
        uint64_t result = 0;
        for (int i = 0; i < 8; i++) {
            result |= ((uint64_t)hash[i]) << (8 * i);
        }
        return result;
    } else if (strcmp(type, "int") == 0 || strcmp(type, "cryptographic") == 0) {
        uint64_t int_value = strtoull(value, NULL, 10);
        return poseidon(&int_value, 1);
    }
    return 0;
}

char* create_pod_pcd(const uint8_t* privateKey, const char* data) {
    // Parse the JSON data (simplified for this example)
    // In a real implementation, you'd use a JSON parser
    uint64_t hashes[100];  // Assuming max 50 key-value pairs
    int hash_count = 0;

    // Tokenize the data string and compute hashes
    char* data_copy = strdup(data);
    char* token = strtok(data_copy, ",");
    while (token != NULL) {
        char* key = strtok(token, ":");
        char* value = strtok(NULL, "");
        char* type = strchr(value, '"') ? "string" : "int";  // Simplified type detection

        hashes[hash_count++] = pod_hash(key, key, "string");
        hashes[hash_count++] = pod_hash(key, value, type);

        token = strtok(NULL, ",");
    }
    free(data_copy);

    uint64_t message = leanIMT(hashes, hash_count);
    EdDSASignature sign = eddsa_poseidon_sign(privateKey, message);

    // Generate UUID (simplified)
    char uuid[37];
    for (int i = 0; i < 36; i++) {
        uuid[i] = "0123456789abcdef"[esp_random() % 16];
        if (i == 8 || i == 13 || i == 18 || i == 23) uuid[i] = '-';
    }
    uuid[36] = '\0';

    // Base64 encode public key and signature
    size_t pk_b64_len, sig_b64_len;
    mbedtls_base64_encode(NULL, 0, &pk_b64_len, sign.publicKey, 32);
    mbedtls_base64_encode(NULL, 0, &sig_b64_len, sign.signature, 64);

    char* pk_b64 = malloc(pk_b64_len);
    char* sig_b64 = malloc(sig_b64_len);

    mbedtls_base64_encode((unsigned char*)pk_b64, pk_b64_len, &pk_b64_len, sign.publicKey, 32);
    mbedtls_base64_encode((unsigned char*)sig_b64, sig_b64_len, &sig_b64_len, sign.signature, 64);

    // Construct the JSON output
    char* result = malloc(1024);  // Adjust size as needed
    snprintf(result, 1024,
             "{\"id\":\"%s\",\"claim\":{\"entries\":%s,\"signerPublicKey\":\"%s\"},"
             "\"proof\":{\"signature\":\"%s\"}}",
             uuid, data, pk_b64, sig_b64);

    free(pk_b64);
    free(sig_b64);

    return result;
}

void app_main() {
    char cwd[PATH_MAX];
    
    // Get the current working directory
    if (getcwd(cwd, sizeof(cwd)) != NULL) {
        printf("Current working dir: %s\n", cwd);
    } else {
        perror("getcwd() error");
    }

    uint8_t privateKey[32] = {0};  // All zeros for this example
    const char* data = "{\"attack\":{\"type\":\"int\",\"value\":7},"
                       "\"itemSet\":{\"type\":\"string\",\"value\":\"celestial\"},"
                       "\"pod_type\":{\"type\":\"string\",\"value\":\"item.weapon\"},"
                       "\"weaponType\":{\"type\":\"string\",\"value\":\"sword\"}}";

    char* pcd = create_pod_pcd(privateKey, data);
    printf("PCD: %s\n", pcd);
    free(pcd);
}