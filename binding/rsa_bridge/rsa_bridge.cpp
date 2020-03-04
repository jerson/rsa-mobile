#include "rsa_bridge.h"
#include <iostream>

KeyPair buildKeyPair(char * publicKey,char * privateKey)
{
  KeyPair keyPair;
  keyPair.publicKey = publicKey;
  keyPair.publicKey = privateKey;
  return keyPair;
}

void error_generate_throw(char * message)
{
  throw message;
}