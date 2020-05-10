package rsa

import (
	"encoding/json"
	"github.com/lestrrat-go/jwx/jwk"
)

func (r *FastRSA) ConvertPublicKeyToPKIX(publicKey string) (string, error) {

	publicKeyCertKeyBase, err := r.readPublicKey(publicKey)
	if err != nil {
		return "", err
	}

	output, err := encodePublicKey(publicKeyCertKeyBase, PublicKeyFormatTypePKIX)
	if err != nil {
		return "", err
	}

	return string(output), nil
}

func (r *FastRSA) ConvertPublicKeyToPKCS1(publicKey string) (string, error) {

	publicKeyCertKeyBase, err := r.readPublicKey(publicKey)
	if err != nil {
		return "", err
	}

	output, err := encodePublicKey(publicKeyCertKeyBase, PublicKeyFormatTypePKCS1)
	if err != nil {
		return "", err
	}

	return string(output), nil
}

func (r *FastRSA) ConvertPublicKeyToJWK(privateKey string) (string, error) {

	publicKeyCertKeyBase, err := r.readPublicKey(privateKey)
	if err != nil {
		return "", err
	}

	key, err := jwk.New(publicKeyCertKeyBase)
	if err != nil {
		return "", err
	}

	encoded, err := json.MarshalIndent(key, "", "  ")
	if err != nil {
		return "", err
	}

	return string(encoded), nil
}
