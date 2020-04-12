package rsa

import (
	"crypto/rand"
	"encoding/base64"
	"github.com/keybase/go-crypto/rsa"
)

func (r *FastRSA) SignPSS(message, hashName, saltLengthName, privateKey string) (string, error) {

	output, err := r.signPSS([]byte(message), hashName, saltLengthName, privateKey)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(output), nil
}

func (r *FastRSA) SignPSSBytes(message []byte, hashName, saltLengthName, privateKey string) ([]byte, error) {
	return r.signPSS(message, hashName, saltLengthName, privateKey)
}

func (r *FastRSA) signPSS(message []byte, hashName, saltLengthName, privateKey string) ([]byte, error) {

	private, err := r.readPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	hash := getHashInstance(hashName)
	_, err = hash.Write(message)
	if err != nil {
		return nil, err
	}

	signature, err := rsa.SignPSS(rand.Reader, private, getHashType(hashName), hash.Sum(nil), &rsa.PSSOptions{
		SaltLength: getSaltLength(saltLengthName),
		Hash:       getHashType(hashName),
	})
	if err != nil {
		return nil, err
	}

	return signature, nil
}
