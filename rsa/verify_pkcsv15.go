package rsa

import (
	"encoding/base64"
	"github.com/keybase/go-crypto/rsa"
	"io"
)

func (r *FastRSA) VerifyPKCS1v15(signature, message, hashName, publicKey string) (bool, error) {
	public, err := r.readPublicKey(publicKey)
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

	err = rsa.VerifyPKCS1v15(public, hashTo(hashName), hash.Sum(nil), signatureBytes)
	if err != nil {
		return false, err
	}

	return true, nil
}
