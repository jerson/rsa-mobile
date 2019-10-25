package rsa

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
)

func (r *RSA) Verify(signature, hash, hashName, pkcs12, passphrase string) (bool, error) {
	privateKey, _, err := r.readPKCS12(pkcs12, passphrase)
	if err != nil {
		return false, err
	}

	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, err
	}
	hashBytes, err := hex.DecodeString(hash)
	if err != nil {
		return false, err
	}
	hashType := hashTo(hashName)

	err = rsa.VerifyPKCS1v15(&privateKey.PublicKey, hashType, hashBytes, signatureBytes)
	if err != nil {
		return false, err
	}

	return true, nil
}
