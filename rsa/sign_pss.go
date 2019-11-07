package rsa

import (
	"crypto/rand"
	"encoding/base64"
	"io"

	"github.com/keybase/go-crypto/rsa"
)

func (r *FastRSA) SignPSS(message, hashName, pkcs12, passphrase string) (string, error) {

	privateKey, _, err := r.readPKCS12(pkcs12, passphrase)
	if err != nil {
		return "", err
	}

	hash := getHashInstance(hashName)
	_, err = io.WriteString(hash, message)
	if err != nil {
		return "", err
	}

	signature, err := rsa.SignPSS(rand.Reader, privateKey, hashTo(hashName), hash.Sum(nil), &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       hashTo(hashName),
	})
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(signature), nil
}
