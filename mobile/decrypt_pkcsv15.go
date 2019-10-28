package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
)

func (r *FastRSA) DecryptPKCS1v15(ciphertext, pkcs12, passphrase string) (string, error) {

	privateKey, _, err := r.readPKCS12(pkcs12, passphrase)
	if err != nil {
		return "", err
	}
	ciphertextDecoded, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	output, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, ciphertextDecoded)
	if err != nil {
		return "", err
	}

	return string(output), nil
}
