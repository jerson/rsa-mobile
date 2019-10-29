package rsa

import (
	"crypto/rsa"
	"encoding/base64"
	"io"
)

func (r *FastRSA) VerifyPSS(signature, message, hashName, pkcs12, passphrase string) (bool, error) {
	privateKey, _, err := r.readPKCS12(pkcs12, passphrase)
	if err != nil {
		return false, err
	}

	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, err
	}

	hash := getHashInstance(hashName)
	_, err = io.WriteString(hash, message)
	if err != nil {
		return false, err
	}

	err = rsa.VerifyPSS(&privateKey.PublicKey, hashTo(hashName), hash.Sum(nil), signatureBytes, nil)
	if err != nil {
		return false, err
	}

	return true, nil
}
