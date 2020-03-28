package rsa

import (
	"crypto/rand"
	"encoding/base64"
	"github.com/keybase/go-crypto/rsa"
)

func (r *FastRSA) DecryptPKCS1v15(ciphertext, privateKey string) (string, error) {

	private, err := r.readPrivateKey(privateKey)
	if err != nil {
		return "", err
	}
	ciphertextDecoded, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	output, err := rsa.DecryptPKCS1v15(rand.Reader, private, ciphertextDecoded)
	if err != nil {
		return "", err
	}

	return string(output), nil
}
