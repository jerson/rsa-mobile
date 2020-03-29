package rsa

import (
	"crypto/rand"
	"github.com/keybase/go-crypto/rsa"
)

type KeyPair struct {
	PrivateKey string
	PublicKey  string
}

func (r *FastRSA) Generate(nBits int) (*KeyPair, error) {

	var keyPair *KeyPair
	key, err := rsa.GenerateKey(rand.Reader, nBits)
	if err != nil {
		return keyPair, err
	}

	privateKey, err := encodePrivateKey(key, PrivateKeyFormatTypePKCS1)
	if err != nil {
		return nil, err
	}
	publicKeySource, err := publicFromPrivate(key)
	if err != nil {
		return nil, err
	}
	publicKey, err := encodePublicKey(publicKeySource, PublicKeyFormatTypePKCS1)
	if err != nil {
		return nil, err
	}

	keyPair = &KeyPair{
		PrivateKey: string(privateKey),
		PublicKey:  string(publicKey),
	}
	return keyPair, nil
}
