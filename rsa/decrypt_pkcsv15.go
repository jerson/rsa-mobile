package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
)

func (r *FastRSA) DecryptPKCS1v15(ciphertext, privateKey string) (string, error) {

	ciphertextDecoded, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	output, err := r.decryptPKCS1v15(ciphertextDecoded, privateKey)
	if err != nil {
		return "", err
	}

	return string(output), nil
}

func (r *FastRSA) DecryptPKCS1v15Bytes(ciphertext []byte, privateKey string) ([]byte, error) {
	return r.decryptPKCS1v15(ciphertext, privateKey)
}

func (r *FastRSA) decryptPKCS1v15(ciphertext []byte, privateKey string) ([]byte, error) {

	private, err := r.readPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	output, err := rsa.DecryptPKCS1v15(rand.Reader, private, ciphertext)
	if err != nil {
		return nil, err
	}

	return output, nil
}
