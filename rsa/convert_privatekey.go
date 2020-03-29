package rsa

import (
	"encoding/json"
	"github.com/lestrrat-go/jwx/jwk"
)

func (r *FastRSA) ConvertPrivateKeyToPKCS8(privateKey string) (string, error) {

	privateKeyCertKeyBase, err := r.readPrivateKey(privateKey)
	if err != nil {
		return "", err
	}

	output, err := encodePrivateKey(privateKeyCertKeyBase, PrivateKeyFormatTypePKCS8)
	if err != nil {
		return "", err
	}

	return string(output), nil
}

func (r *FastRSA) ConvertPrivateKeyToPKCS1(privateKey string) (string, error) {

	privateKeyCertKeyBase, err := r.readPrivateKey(privateKey)
	if err != nil {
		return "", err
	}

	output, err := encodePrivateKey(privateKeyCertKeyBase, PrivateKeyFormatTypePKCS1)
	if err != nil {
		return "", err
	}

	return string(output), nil
}

func (r *FastRSA) ConvertPrivateKeyToJWK(privateKey string) (string, error) {

	privateKeyCertKeyBase, err := r.readPrivateKey(privateKey)
	if err != nil {
		return "", err
	}

	key, err := jwk.New(toCryptoRSAPrivateKey(privateKeyCertKeyBase))
	if err != nil {
		return "", err
	}

	encoded, err := json.MarshalIndent(key, "", "  ")
	if err != nil {
		return "", err
	}

	return string(encoded), nil
}
