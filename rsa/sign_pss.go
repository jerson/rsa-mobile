package rsa

import (
	"crypto/rand"
	"encoding/base64"
	"io"

	"github.com/keybase/go-crypto/rsa"
)

func (r *FastRSA) SignPSS(message, hashName, saltLengthName, privateKey string) (string, error) {

	private, err := r.readPrivateKey(privateKey)
	if err != nil {
		return "", err
	}

	saltLength := getSaltLength(saltLengthName)
	hash := getHashInstance(hashName)
	_, err = io.WriteString(hash, message)
	if err != nil {
		return "", err
	}

	signature, err := rsa.SignPSS(rand.Reader, private, getHashType(hashName), hash.Sum(nil), &rsa.PSSOptions{
		SaltLength: saltLength,
		Hash:       getHashType(hashName),
	})
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(signature), nil
}
