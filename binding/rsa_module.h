#ifndef RSA_MODULE_STRUCT_H
#define RSA_MODULE_STRUCT_H
typedef struct { char *public_key; char *private_key; } KeyPair;
#endif

#ifdef __cplusplus
extern "C" {
#endif

extern KeyPair build_key_pair(char *public_key, char *private_key);

extern void error_generate_throw(char *message);

#ifdef __cplusplus
}
#endif
