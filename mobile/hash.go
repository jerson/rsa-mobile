package rsa

import (
	"encoding/base64"
	"encoding/hex"
	"io"
)

func (r *RSA) Hash(message, name string) (string, error) {

	hash := getHashInstance(name)
	_, err := io.WriteString(hash, message)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

func (r *RSA) Base64(message, name string) (string, error) {
	return base64.StdEncoding.EncodeToString([]byte(message)), nil
}
