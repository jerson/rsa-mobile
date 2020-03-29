package rsa

import (
	"crypto/x509"
	"encoding/pem"
)

func (r *FastRSA) DecryptPrivateKey(privateKeyEncrypted, password string) (string, error) {

	block, _ := pem.Decode([]byte(privateKeyEncrypted))
	der, err := x509.DecryptPEMBlock(block, []byte(password))
	if err != nil {
		return "", err
	}

	// TODO should be valid choose custom marshal
	privateKeyCertKeyBase, err := x509.ParsePKCS1PrivateKey(der)
	if err != nil {
		return "", err
	}

	output, err := encodePrivateKey(privateKeyCertKeyBase, PrivateKeyFormatTypePKCS1)
	if err != nil {
		return "", err
	}

	return string(output), nil
}
