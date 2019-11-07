package rsa

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"github.com/keybase/go-crypto/rsa"
)

type KeyPair struct {
	PublicKey  string
	PrivateKey string
}

func (r *FastRSA) Generate(nBits int) (*KeyPair, error) {

	var keyPair *KeyPair
	key, err := rsa.GenerateKey(rand.Reader, nBits)
	if err != nil {
		return keyPair, err
	}

	keybaseRSA := toCryptoRSA(key)
	privateKey := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(keybaseRSA),
		},
	)
	publicKey := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(&keybaseRSA.PublicKey),
		},
	)
	keyPair = &KeyPair{
		PublicKey:  string(publicKey),
		PrivateKey: string(privateKey),
	}

	return keyPair, nil
}
