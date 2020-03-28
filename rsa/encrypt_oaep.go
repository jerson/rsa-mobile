package rsa

import (
	"crypto/rand"
	"encoding/base64"
	"github.com/keybase/go-crypto/rsa"
)

func (r *FastRSA) EncryptOAEP(message, label, hashName, publicKey string) (string, error) {

	public, err := r.readPublicKey(publicKey)
	if err != nil {
		return "", err
	}

	output, err := rsa.EncryptOAEP(
		getHashInstance(hashName),
		rand.Reader,
		public,
		[]byte(message),
		[]byte(label),
	)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(output), nil
}
