#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "rsa_module.h"

#ifndef RSA_MODULE_C
#define RSA_MODULE_C

//#include <iostream>

KeyPair build_key_pair(char * public_key,char * private_key)
{
  KeyPair key_pair;
  key_pair.public_key = public_key;
  key_pair.private_key = private_key;
  return key_pair;
}
/*
void error_generate_throw(char * message)
{
  printf("Error: %s\n", message);
  // throw message;
}*/

#endif