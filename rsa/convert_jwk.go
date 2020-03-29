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

	var key interface{}
	if keyID != "" {
		keys := set.LookupKeyID(keyID)
		if len(keys) == 0 {
			return "", fmt.Errorf("key not found: %s", keyID)
		}

		key, err = keys[0].Materialize()
		if err != nil {
			return "", err
		}
	} else {
		key, err = set.Keys[0].Materialize()
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

	var key interface{}
	if keyID != "" {
		keys := set.LookupKeyID(keyID)
		if len(keys) == 0 {
			return "", fmt.Errorf("key not found: %s", keyID)
		}

		key, err = keys[0].Materialize()
		if err != nil {
			return "", err
		}
	} else {
		key, err = set.Keys[0].Materialize()
	}

	output, err := encodePublicKey(key, PublicKeyFormatTypePKCS1)
	if err != nil {
		return "", err
	}

	return string(output), nil
}
