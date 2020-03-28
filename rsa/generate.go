package rsa

import (
	"crypto/rand"
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

	privateKey, err := encodePrivateKey(key)
	if err != nil {
		return nil, err
	}
	publicKeySource, err := publicFromPrivate(key)
	if err != nil {
		return nil, err
	}
	publicKey, err := encodePublicKey(publicKeySource)
	if err != nil {
		return nil, err
	}

	keyPair = &KeyPair{
		PublicKey:  string(publicKey),
		PrivateKey: string(privateKey),
	}
	return keyPair, nil
}
