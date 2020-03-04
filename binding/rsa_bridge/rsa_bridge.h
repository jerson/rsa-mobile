#ifndef RSA_MOBILE_H
#define RSA_MOBILE_H

#include <iostream>
#include <vector>

typedef struct { char *publicKey; char *privateKey; } KeyPair;

KeyPair buildKeyPair(char *publicKey, char *privateKey);

void errorGenerateThrow(char *message);

#endif
