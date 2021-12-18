package rsa

import (
	"crypto/rand"
	"crypto/x509"
)

func (r *FastRSA) EncryptPrivateKey(privateKey, password, cipherName string) (string, error) {

	privateKeyCertKeyBase, err := r.readPrivateKey(privateKey)
	if err != nil {
		return "", err
	}

	// TODO should be valid choose custom marshal
	pemBytes := x509.MarshalPKCS1PrivateKey(privateKeyCertKeyBase)
	block, err := x509.EncryptPEMBlock(rand.Reader, getPrivateKeyHeaderByType(PrivateKeyFormatTypePKCS1), pemBytes, []byte(password), getPEMCipher(cipherName))
	if err != nil {
		return "", err
	}
	output, err := encodePem(block)
	if err != nil {
		return "", err
	}
	return string(output), err
}
