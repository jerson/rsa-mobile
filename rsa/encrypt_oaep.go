package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
)

func (r *FastRSA) EncryptOAEP(message, label, hashName, publicKey string) (string, error) {
	output, err := r.encryptOAEP([]byte(message), label, hashName, publicKey)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(output), nil
}
func (r *FastRSA) EncryptOAEPBytes(message []byte, label, hashName, publicKey string) ([]byte, error) {
	return r.encryptOAEP(message, label, hashName, publicKey)
}

func (r *FastRSA) encryptOAEP(message []byte, label, hashName, publicKey string) ([]byte, error) {

	public, err := r.readPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	output, err := rsa.EncryptOAEP(
		getHashInstance(hashName),
		rand.Reader,
		public,
		message,
		[]byte(label),
	)
	if err != nil {
		return nil, err
	}

	return output, nil
}
