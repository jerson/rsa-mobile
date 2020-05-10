package rsa

import (
	"crypto/rand"
	"encoding/base64"

	"crypto/rsa"
)

func (r *FastRSA) DecryptOAEP(ciphertext, label, hashName, privateKey string) (string, error) {

	ciphertextDecoded, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	output, err := r.decryptOAEP(ciphertextDecoded, label, hashName, privateKey)
	if err != nil {
		return "", err
	}

	return string(output), nil
}

func (r *FastRSA) DecryptOAEPBytes(ciphertext []byte, label, hashName, privateKey string) ([]byte, error) {
	return r.decryptOAEP(ciphertext, label, hashName, privateKey)
}

func (r *FastRSA) decryptOAEP(ciphertext []byte, label, hashName, privateKey string) ([]byte, error) {

	private, err := r.readPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	output, err := rsa.DecryptOAEP(
		getHashInstance(hashName),
		rand.Reader,
		private,
		ciphertext,
		[]byte(label),
	)
	if err != nil {
		return nil, err
	}

	return output, nil
}
