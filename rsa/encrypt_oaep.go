package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
)

func (r *FastRSA) EncryptOAEP(message, label, hashName, publicKey string) (string, error) {
	output, err := r.encryptOAEP([]byte(message), label, hashName, publicKey)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(output), nil
}
func (r *FastRSA) EncryptOAEPBytes(message []byte, label, hashName, publicKey string) ([]byte, error) {
	return r.encryptOAEP(message, label, hashName, publicKey)
}

func (r *FastRSA) encryptOAEP(message []byte, label, hashName, publicKey string) ([]byte, error) {

	public, err := r.readPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	hash := getHashInstance(hashName)
	// https://www.rfc-editor.org/rfc/rfc8017#section-7.1.1
	//M  message to be encrypted, an octet string of length mLen,
	//   where mLen <= k - 2hLen - 2
	offset := public.Size() - 2*hash.Size() - 2

	return processChunk(len(message), offset, func(i, to int) ([]byte, error) {
		return rsa.EncryptOAEP(hash, rand.Reader, public, message[i:to], []byte(label))
	})

}
