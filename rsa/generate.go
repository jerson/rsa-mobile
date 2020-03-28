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

	keybaseRSA := toCryptoRSAPrivateKey(key)
	privateKey := encodePrivateKey(keybaseRSA)
	publicKey := encodePublicKey(&keybaseRSA.PublicKey)
	keyPair = &KeyPair{
		PublicKey:  string(publicKey),
		PrivateKey: string(privateKey),
	}
	return keyPair, nil
}
