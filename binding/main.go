package main

/*
#include <dummy.cc>
#include <stdlib.h>
#include <string.h>
#include <iostream>

void error(char *message) {
   throw message;
}
*/
import "C"
import (
	"github.com/jerson/rsa-mobile/rsa"
)

var instance = rsa.NewFastRSA()

//export DecryptOAEP
func DecryptOAEP(ciphertext, label, hashName, pkcs12, passphrase *C.char) *C.char {
	result, err := instance.DecryptOAEP(C.GoString(ciphertext), C.GoString(label), C.GoString(hashName), C.GoString(pkcs12), C.GoString(passphrase))
	if err != nil {
		C.error(C.CString(err.Error()))
		return nil
	}
	return C.CString(result)
}

//export DecryptPKCS1v15
func DecryptPKCS1v15(ciphertext, pkcs12, passphrase *C.char) *C.char {
	result, err := instance.DecryptPKCS1v15(C.GoString(ciphertext), C.GoString(pkcs12), C.GoString(passphrase))
	if err != nil {
		C.error(C.CString(err.Error()))
		return nil
	}
	return C.CString(result)
}

//export EncryptOAEP
func EncryptOAEP(message, label, hashName, pkcs12, passphrase *C.char) *C.char {
	result, err := instance.EncryptOAEP(C.GoString(message), C.GoString(label), C.GoString(hashName), C.GoString(pkcs12), C.GoString(passphrase))
	if err != nil {
		C.error(C.CString(err.Error()))
		return nil
	}
	return C.CString(result)
}

//export EncryptPKCS1v15
func EncryptPKCS1v15(message, pkcs12, passphrase *C.char) *C.char {
	result, err := instance.EncryptPKCS1v15(C.GoString(message), C.GoString(pkcs12), C.GoString(passphrase))
	if err != nil {
		C.error(C.CString(err.Error()))
		return nil
	}
	return C.CString(result)
}

//export Generate
func Generate(nBits int) map[*C.char]*C.char {
	result, err := instance.Generate(nBits)
	if err != nil {
		C.error(C.CString(err.Error()))
		return nil
	}
	return map[*C.char]*C.char{
		C.CString("publicKey"):  C.CString(result.PublicKey),
		C.CString("privateKey"): C.CString(result.PrivateKey),
	}
}

//export Hash
func Hash(message, name *C.char) *C.char {
	result, err := instance.Hash(C.GoString(message), C.GoString(name))
	if err != nil {
		C.error(C.CString(err.Error()))
		return nil
	}
	return C.CString(result)
}

//export Base64
func Base64(message *C.char) *C.char {
	result, err := instance.Base64(C.GoString(message))
	if err != nil {
		C.error(C.CString(err.Error()))
		return nil
	}
	return C.CString(result)
}

//export SignPKCS1v15
func SignPKCS1v15(message, hashName, pkcs12, passphrase *C.char) *C.char {
	result, err := instance.SignPKCS1v15(C.GoString(message), C.GoString(hashName), C.GoString(pkcs12), C.GoString(passphrase))
	if err != nil {
		C.error(C.CString(err.Error()))
		return nil
	}
	return C.CString(result)
}

//export SignPSS
func SignPSS(message, hashName, pkcs12, passphrase *C.char) *C.char {
	result, err := instance.SignPSS(C.GoString(message), C.GoString(hashName), C.GoString(pkcs12), C.GoString(passphrase))
	if err != nil {
		C.error(C.CString(err.Error()))
		return nil
	}
	return C.CString(result)
}

//export VerifyPKCS1v15
func VerifyPKCS1v15(signature, message, hashName, pkcs12, passphrase *C.char) *C.char {
	result, err := instance.VerifyPKCS1v15(C.GoString(signature), C.GoString(message), C.GoString(hashName), C.GoString(pkcs12), C.GoString(passphrase))
	if err != nil {
		C.error(C.CString(err.Error()))
		return nil
	}
	if result {
		return C.CString("1")
	}
	return C.CString("")
}

//export VerifyPSS
func VerifyPSS(signature, message, hashName, pkcs12, passphrase *C.char) *C.char {
	result, err := instance.VerifyPSS(C.GoString(signature), C.GoString(message), C.GoString(hashName), C.GoString(pkcs12), C.GoString(passphrase))
	if err != nil {
		C.error(C.CString(err.Error()))
		return nil
	}
	if result {
		return C.CString("1")
	}
	return C.CString("")
}

func main() {}
