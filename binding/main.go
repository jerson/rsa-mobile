package main

import "C"
import (
	"github.com/jerson/rsa-mobile/rsa"
)

var instance = rsa.NewFastRSA()

//export DecryptOAEP
func DecryptOAEP(ciphertext, label, hashName, pkcs12, passphrase string) (string, error) {
	return instance.DecryptOAEP(ciphertext, label, hashName, pkcs12, passphrase)
}

//export DecryptPKCS1v15
func DecryptPKCS1v15(ciphertext, pkcs12, passphrase string) (string, error) {
	return instance.DecryptPKCS1v15(ciphertext, pkcs12, passphrase)
}

//export EncryptOAEP
func EncryptOAEP(message, label, hashName, pkcs12, passphrase string) (string, error) {
	return instance.EncryptOAEP(message, label, hashName, pkcs12, passphrase)
}

//export EncryptPKCS1v15
func EncryptPKCS1v15(message, pkcs12, passphrase string) (string, error) {
	return instance.EncryptPKCS1v15(message, pkcs12, passphrase)
}

//export Generate
func Generate(nBits int) (map[string]string, error) {
	result, err := instance.Generate(nBits)
	if err != nil {
		return nil, err
	}
	return map[string]string{
		"publicKey":  result.PublicKey,
		"privateKey": result.PrivateKey,
	}, err
}

//export Hash
func Hash(message, name string) (string, error) {
	return instance.Hash(message, name)
}

//export SignPKCS1v15
func SignPKCS1v15(message, hashName, pkcs12, passphrase string) (string, error) {
	return instance.SignPKCS1v15(message, hashName, pkcs12, passphrase)
}

//export SignPSS
func SignPSS(message, hashName, pkcs12, passphrase string) (string, error) {
	return instance.SignPSS(message, hashName, pkcs12, passphrase)
}

//export VerifyPKCS1v15
func VerifyPKCS1v15(signature, message, hashName, pkcs12, passphrase string) (bool, error) {
	return instance.VerifyPKCS1v15(signature, message, hashName, pkcs12, passphrase)
}

//export VerifyPSS
func VerifyPSS(signature, message, hashName, pkcs12, passphrase string) (bool, error) {
	return instance.VerifyPSS(signature, message, hashName, pkcs12, passphrase)
}

func main() {}
