package rsa

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
)

func (r *FastRSA) EncryptPrivateKey(privateKey, password, cipherName string) (string, error) {

	privateKeyCertKeyBase, err := r.readPrivateKey(privateKey)
	if err != nil {
		return "", err
	}

	// TODO should be valid choose custom marshal
	pemBytes := x509.MarshalPKCS1PrivateKey(toCryptoRSAPrivateKey(privateKeyCertKeyBase))
	block, err := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", pemBytes, []byte(password), getPEMCipher(cipherName))
	if err != nil {
		return "", err
	}
	output := pem.EncodeToMemory(block)

	return string(output), nil
}
