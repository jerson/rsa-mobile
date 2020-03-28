package rsa

import (
	"crypto/rand"
	"encoding/base64"
	"github.com/keybase/go-crypto/rsa"
)

func (r *FastRSA) EncryptPKCS1v15(message, publicKey string) (string, error) {

	public, err := r.readPublicKey(publicKey)
	if err != nil {
		return "", err
	}

	output, err := rsa.EncryptPKCS1v15(rand.Reader, public, []byte(message))
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(output), nil
}
