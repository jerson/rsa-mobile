package rsa

import (
	"crypto/rand"
	"github.com/keybase/go-crypto/rsa"
)

type KeyPair struct {
	PublicKey  string
	PrivateKey string
}
type EncodeOptions struct {
	PublicKeyFormat  string
	PrivateKeyFormat string
}

func (r *FastRSA) Generate(nBits int, options *EncodeOptions) (*KeyPair, error) {

	var keyPair *KeyPair
	key, err := rsa.GenerateKey(rand.Reader, nBits)
	if err != nil {
		return keyPair, err
	}

	privateKey, err := encodePrivateKey(key, getPrivateKeyFormatType(options.PrivateKeyFormat))
	if err != nil {
		return nil, err
	}
	publicKeySource, err := publicFromPrivate(key)
	if err != nil {
		return nil, err
	}
	publicKey, err := encodePublicKey(publicKeySource, getPublicKeyFormatType(options.PublicKeyFormat))
	if err != nil {
		return nil, err
	}

	keyPair = &KeyPair{
		PublicKey:  string(publicKey),
		PrivateKey: string(privateKey),
	}
	return keyPair, nil
}
