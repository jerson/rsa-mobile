package rsa

import (
	"crypto/rand"
	"encoding/base64"
	"github.com/keybase/go-crypto/rsa"
	"io"
)

func (r *FastRSA) SignPKCS1v15(message, hashName, pkcs12, passphrase string) (string, error) {

	privateKey, _, err := r.readPKCS12(pkcs12, passphrase)
	if err != nil {
		return "", err
	}

	hash := getHashInstance(hashName)
	_, err = io.WriteString(hash, message)
	if err != nil {
		return "", err
	}

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, hashTo(hashName), hash.Sum(nil))
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(signature), nil
}
