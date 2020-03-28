package rsa

import (
	"encoding/base64"
	"github.com/keybase/go-crypto/rsa"
	"io"
)

func (r *FastRSA) VerifyPSS(signature, message, hashName, saltLengthName, publicKey string) (bool, error) {
	public, err := r.readPublicKey(publicKey)
	if err != nil {
		return false, err
	}

	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, err
	}

	saltLength := getSaltLength(saltLengthName)
	hash := getHashInstance(hashName)
	_, err = io.WriteString(hash, message)
	if err != nil {
		return false, err
	}

	err = rsa.VerifyPSS(public, getHashType(hashName), hash.Sum(nil), signatureBytes, &rsa.PSSOptions{
		SaltLength: saltLength,
		Hash:       getHashType(hashName),
	})
	if err != nil {
		return false, err
	}

	return true, nil
}
