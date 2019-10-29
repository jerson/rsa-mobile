package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
)

func (r *FastRSA) EncryptOAEP(message, label, hashName, pkcs12, passphrase string) (string, error) {

	privateKey, _, err := r.readPKCS12(pkcs12, passphrase)
	if err != nil {
		return "", err
	}

	output, err := rsa.EncryptOAEP(
		getHashInstance(hashName),
		rand.Reader,
		&privateKey.PublicKey,
		[]byte(message),
		[]byte(label),
	)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(output), nil
}
