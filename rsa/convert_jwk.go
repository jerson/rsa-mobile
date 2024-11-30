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

func getJWKKey(keyID string, set jwk.Set) (interface{}, error) {
	var key interface{}
	if keyID != "" {
		keyFound, ok := set.LookupKeyID(keyID)
		if !ok {
			return nil, fmt.Errorf("key not found: %s", keyID)
		}

		err := keyFound.Raw(&key)
		return key, err
	} else {
		keyFound, ok := set.Get(0)
		if !ok {
			return nil, fmt.Errorf("no key found")
		}
		err := keyFound.Raw(&key)
		return key, err
	}
}
