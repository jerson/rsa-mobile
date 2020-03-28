package rsa

import (
	"crypto/rand"
	"encoding/base64"
	"github.com/keybase/go-crypto/rsa"
)

func (r *FastRSA) DecryptOAEP(ciphertext, label, hashName, privateKey string) (string, error) {

	private, err := r.readPrivateKey(privateKey)
	if err != nil {
		return "", err
	}
	ciphertextDecoded, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	output, err := rsa.DecryptOAEP(
		getHashInstance(hashName),
		rand.Reader,
		private,
		ciphertextDecoded,
		[]byte(label),
	)
	if err != nil {
		return "", err
	}

	return string(output), nil
}
