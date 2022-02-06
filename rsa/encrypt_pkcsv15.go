package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
)

func (r *FastRSA) EncryptPKCS1v15(message, publicKey string) (string, error) {

	output, err := r.encryptPKCS1v15([]byte(message), publicKey)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(output), nil
}

func (r *FastRSA) EncryptPKCS1v15Bytes(message []byte, publicKey string) ([]byte, error) {
	return r.encryptPKCS1v15(message, publicKey)
}

func (r *FastRSA) encryptPKCS1v15(message []byte, publicKey string) ([]byte, error) {

	public, err := r.readPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	// https://www.rfc-editor.org/rfc/rfc8017#section-7.2.1
	// M  message to be encrypted, an octet string of length
	//    mLen, where mLen <= k - 11
	offset := public.Size() - 11

	return processChunk(len(message), offset, func(i, to int) ([]byte, error) {
		return rsa.EncryptPKCS1v15(rand.Reader, public, message[i:to])
	})
}
