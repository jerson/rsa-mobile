package rsa

import (
	"encoding/base64"
	"encoding/hex"
	"io"
)

func (r *FastRSA) Hash(message, name string) (string, error) {

	hash := getHashInstance(name)
	_, err := io.WriteString(hash, message)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

func (r *FastRSA) Base64(message string) (string, error) {
	return base64.StdEncoding.EncodeToString([]byte(message)), nil
}
