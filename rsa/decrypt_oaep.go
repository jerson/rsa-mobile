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

	hash := getHashInstance(hashName)
	// https://www.rfc-editor.org/rfc/rfc8017#section-7.1.2
	return processChunk(len(ciphertext), private.PublicKey.Size(), func(i, to int) ([]byte, error) {
		return rsa.DecryptOAEP(hash, rand.Reader, private, ciphertext[i:to], []byte(label))
	})

}
