#include "rsa_bridge.h"
#include <iostream>

void errorGenerateThrow(char * message)
{
  throw *message;
}