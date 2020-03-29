package rsa

import (
	"fmt"
	"github.com/lestrrat-go/jwx/jwk"
)

func (r *FastRSA) ConvertJWKToPrivateKey(data, keyID string) (string, error) {

	set, err := jwk.ParseString(data)
	if err != nil {
		return "", err
	}

	key, err := getJWKKey(keyID, set)
	if err != nil {
		return "", err
	}

	output, err := encodePrivateKey(key, PrivateKeyFormatTypePKCS1)
	if err != nil {
		return "", err
	}

	return string(output), nil
}

func (r *FastRSA) ConvertJWKToPublicKey(data, keyID string) (string, error) {

	set, err := jwk.ParseString(data)
	if err != nil {
		return "", err
	}

	key, err := getJWKKey(keyID, set)
	if err != nil {
		return "", err
	}

	output, err := encodePublicKey(key, PublicKeyFormatTypePKCS1)
	if err != nil {
		return "", err
	}

	return string(output), nil
}

func getJWKKey(keyID string, set *jwk.Set) (interface{}, error) {
	if keyID != "" {
		keys := set.LookupKeyID(keyID)
		if len(keys) == 0 {
			return nil, fmt.Errorf("key not found: %s", keyID)
		}

		return keys[0].Materialize()
	} else {
		return set.Keys[0].Materialize()
	}
}
