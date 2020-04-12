package rsa

import (
	"crypto/rand"
	"encoding/base64"
	"github.com/keybase/go-crypto/rsa"
)

func (r *FastRSA) EncryptPKCS1v15(message, publicKey string) (string, error) {

	output, err := r.encryptPKCS1v15([]byte(message), publicKey)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(output), nil
}

func (r *FastRSA) EncryptPKCS1v15Bytes(message []byte, publicKey string) ([]byte, error) {
	return r.encryptPKCS1v15(message, publicKey)
}

func (r *FastRSA) encryptPKCS1v15(message []byte, publicKey string) ([]byte, error) {

	public, err := r.readPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	output, err := rsa.EncryptPKCS1v15(rand.Reader, public, []byte(message))
	if err != nil {
		return nil, err
	}

	return output, nil
}
