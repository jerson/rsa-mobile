package rsa

import (
	"crypto/rand"
	"encoding/base64"
	"github.com/keybase/go-crypto/rsa"
)

func (r *FastRSA) SignPKCS1v15(message, hashName, privateKey string) (string, error) {

	output, err := r.signPKCS1v15([]byte(message), hashName, privateKey)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(output), nil
}

func (r *FastRSA) SignPKCS1v15Bytes(message []byte, hashName, privateKey string) ([]byte, error) {
	return r.signPKCS1v15(message, hashName, privateKey)
}

func (r *FastRSA) signPKCS1v15(message []byte, hashName, privateKey string) ([]byte, error) {

	private, err := r.readPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	hash := getHashInstance(hashName)
	_, err = hash.Write(message)
	if err != nil {
		return nil, err
	}

	signature, err := rsa.SignPKCS1v15(rand.Reader, private, getHashType(hashName), hash.Sum(nil))
	if err != nil {
		return nil, err
	}

	return signature, nil
}
