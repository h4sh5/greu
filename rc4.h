#ifndef RC4_H
#define RC4_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define N 256   // 2^8
#define DROPN 1024

void swap(unsigned char *a, unsigned char *b) {
    int tmp = *a;
    *a = *b;
    *b = tmp;
}

int KSA(unsigned char *key, unsigned char *S, size_t keylen) {

    
    int j = 0;

    for(int i = 0; i < N; i++)  
        S[i] = i;

    for(int i = 0; i < N; i++) {
        j = (j + S[i] + key[i % keylen]) % N;

        swap(&S[i], &S[j]);
    }

    return 0;
}

int PRGA(unsigned char *S, unsigned char *plaintext, unsigned char *ciphertext, size_t buflen) {

    int i = 0;
    int j = 0;

    for(size_t n = 0; n < buflen; n++) {
        i = (i + 1) % N;
        j = (j + S[i]) % N;

        swap(&S[i], &S[j]);
        int rnd = S[(S[i] + S[j]) % N];

        ciphertext[n] = rnd ^ plaintext[n];

    }

    return 0;
}

void drop(unsigned char *S) { // drop DROPN bytes
    int i = 0;
    int j = 0;
    for(size_t n = 0; n < DROPN; n++) {
        i = (i + 1) % N;
        j = (j + S[i]) % N;

        swap(&S[i], &S[j]);
        S[(S[i] + S[j]) % N];

    }
}

int RC4_drop(unsigned char *key, unsigned char *plaintext, unsigned char *ciphertext, size_t keylen, size_t buflen) {

    unsigned char S[N] = {0,};

    KSA(key, S, keylen);
    drop(S);
    PRGA(S, plaintext, ciphertext, buflen);

    return 0;
}

#endif
