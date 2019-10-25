package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
)

func (r *RSA) Decrypt(message, pkcs12, passphrase string) (string, error) {

	privateKey, _, err := r.readPKCS12(pkcs12, passphrase)
	if err != nil {
		return "", err
	}
	messageDecoded, err := base64.StdEncoding.DecodeString(message)
	if err != nil {
		return "", err
	}
	output, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, messageDecoded)
	if err != nil {
		return "", err
	}

	return string(output), nil
}
