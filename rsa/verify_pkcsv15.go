package rsa

import (
	"crypto/rsa"
	"encoding/base64"
)

func (r *FastRSA) VerifyPKCS1v15(signature, message, hashName, publicKey string) (bool, error) {

	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, err
	}

	return r.verifyPKCS1v15(signatureBytes, []byte(message), hashName, publicKey)
}

func (r *FastRSA) VerifyPKCS1v15Bytes(signature, message []byte, hashName, publicKey string) (bool, error) {
	return r.verifyPKCS1v15(signature, message, hashName, publicKey)
}

func (r *FastRSA) verifyPKCS1v15(signature, message []byte, hashName, publicKey string) (bool, error) {
	public, err := r.readPublicKey(publicKey)
	if err != nil {
		return false, err
	}

	hash := getHashInstance(hashName)
	_, err = hash.Write(message)
	if err != nil {
		return false, err
	}

	err = rsa.VerifyPKCS1v15(public, getHashType(hashName), hash.Sum(nil), signature)
	if err != nil {
		return false, err
	}

	return true, nil
}
