package main

// #include <stdint.h>
// typedef struct { char *privateKey; char *publicKey; } KeyPair;
// typedef struct { char *privateKey; char *publicKey; char *certificate; } PKCS12KeyPair;
import "C"
import (
	"fmt"
	"unsafe"

	"github.com/jerson/rsa-mobile/rsa"
)

var instance = rsa.NewFastRSA()

func errorThrow(err error) {
	fmt.Println(err.Error())
	//rsa_bridge.ErrorGenerateThrow(err.Error())
}

//export ConvertJWKToPrivateKey
func ConvertJWKToPrivateKey(data, keyID *C.char) *C.char {
	result, err := instance.ConvertJWKToPrivateKey(C.GoString(data), C.GoString(keyID))
	if err != nil {
		errorThrow(err)
		return nil
	}
	return C.CString(result)
}

//export ConvertJWKToPublicKey
func ConvertJWKToPublicKey(data, keyID *C.char) *C.char {
	result, err := instance.ConvertJWKToPublicKey(C.GoString(data), C.GoString(keyID))
	if err != nil {
		errorThrow(err)
		return nil
	}
	return C.CString(result)
}

//export ConvertKeyPairToPKCS12
func ConvertKeyPairToPKCS12(privateKey, certificate, passphrase *C.char) *C.char {
	result, err := instance.ConvertKeyPairToPKCS12(C.GoString(privateKey), C.GoString(certificate), C.GoString(passphrase))
	if err != nil {
		errorThrow(err)
		return nil
	}
	return C.CString(result)
}

//export ConvertPKCS12ToKeyPair
func ConvertPKCS12ToKeyPair(pkcs12, passphrase *C.char) C.PKCS12KeyPair {
	result, err := instance.ConvertPKCS12ToKeyPair(C.GoString(pkcs12), C.GoString(passphrase))
	if err != nil {
		errorThrow(err)
		return C.PKCS12KeyPair{C.CString(""), C.CString(""), C.CString("")}
	}
	return C.PKCS12KeyPair{C.CString(result.PrivateKey), C.CString(result.PublicKey), C.CString(result.Certificate)}
}

//export ConvertPrivateKeyToPKCS8
func ConvertPrivateKeyToPKCS8(privateKey *C.char) *C.char {
	result, err := instance.ConvertPrivateKeyToPKCS8(C.GoString(privateKey))
	if err != nil {
		errorThrow(err)
		return nil
	}
	return C.CString(result)
}

//export ConvertPrivateKeyToPKCS1
func ConvertPrivateKeyToPKCS1(privateKey *C.char) *C.char {
	result, err := instance.ConvertPrivateKeyToPKCS1(C.GoString(privateKey))
	if err != nil {
		errorThrow(err)
		return nil
	}
	return C.CString(result)
}

//export ConvertPrivateKeyToJWK
func ConvertPrivateKeyToJWK(privateKey *C.char) *C.char {
	result, err := instance.ConvertPrivateKeyToJWK(C.GoString(privateKey))
	if err != nil {
		errorThrow(err)
		return nil
	}
	return C.CString(result)
}

//export ConvertPrivateKeyToPublicKey
func ConvertPrivateKeyToPublicKey(privateKey *C.char) *C.char {
	result, err := instance.ConvertPrivateKeyToPublicKey(C.GoString(privateKey))
	if err != nil {
		errorThrow(err)
		return nil
	}
	return C.CString(result)
}

//export ConvertPublicKeyToPKIX
func ConvertPublicKeyToPKIX(publicKey *C.char) *C.char {
	result, err := instance.ConvertPublicKeyToPKIX(C.GoString(publicKey))
	if err != nil {
		errorThrow(err)
		return nil
	}
	return C.CString(result)
}

//export ConvertPublicKeyToPKCS1
func ConvertPublicKeyToPKCS1(publicKey *C.char) *C.char {
	result, err := instance.ConvertPublicKeyToPKCS1(C.GoString(publicKey))
	if err != nil {
		errorThrow(err)
		return nil
	}
	return C.CString(result)
}

//export ConvertPublicKeyToJWK
func ConvertPublicKeyToJWK(publicKey *C.char) *C.char {
	result, err := instance.ConvertPublicKeyToJWK(C.GoString(publicKey))
	if err != nil {
		errorThrow(err)
		return nil
	}
	return C.CString(result)
}

//export DecryptPrivateKey
func DecryptPrivateKey(privateKeyEncrypted, password *C.char) *C.char {
	result, err := instance.DecryptPrivateKey(C.GoString(privateKeyEncrypted), C.GoString(password))
	if err != nil {
		errorThrow(err)
		return nil
	}
	return C.CString(result)
}

//export EncryptPrivateKey
func EncryptPrivateKey(privateKeyEncrypted, password, cipherName *C.char) *C.char {
	result, err := instance.EncryptPrivateKey(C.GoString(privateKeyEncrypted), C.GoString(password), C.GoString(cipherName))
	if err != nil {
		errorThrow(err)
		return nil
	}
	return C.CString(result)
}

//export DecryptOAEP
func DecryptOAEP(ciphertext, label, hashName, privateKey *C.char) *C.char {
	result, err := instance.DecryptOAEP(C.GoString(ciphertext), C.GoString(label), C.GoString(hashName), C.GoString(privateKey))
	if err != nil {
		errorThrow(err)
		return nil
	}
	return C.CString(result)
}

//export DecryptOAEPBytes
func DecryptOAEPBytes(ciphertext unsafe.Pointer, label, hashName, privateKey *C.char) unsafe.Pointer {
	result, err := instance.DecryptOAEPBytes(C.GoBytes(ciphertext, C.int(100)), C.GoString(label), C.GoString(hashName), C.GoString(privateKey))
	if err != nil {
		errorThrow(err)
		return nil
	}
	return C.CBytes(result)
}

//export DecryptPKCS1v15
func DecryptPKCS1v15(ciphertext, privateKey *C.char) *C.char {
	result, err := instance.DecryptPKCS1v15(C.GoString(ciphertext), C.GoString(privateKey))
	if err != nil {
		errorThrow(err)
		return nil
	}
	return C.CString(result)
}

//export EncryptOAEP
func EncryptOAEP(message, label, hashName, publicKey *C.char) *C.char {
	result, err := instance.EncryptOAEP(C.GoString(message), C.GoString(label), C.GoString(hashName), C.GoString(publicKey))
	if err != nil {
		errorThrow(err)
		return nil
	}
	return C.CString(result)
}

//export EncryptPKCS1v15
func EncryptPKCS1v15(message, publicKey *C.char) *C.char {
	result, err := instance.EncryptPKCS1v15(C.GoString(message), C.GoString(publicKey))
	if err != nil {
		errorThrow(err)
		return nil
	}
	return C.CString(result)
}

//export Generate
func Generate(nBits int) C.KeyPair {
	result, err := instance.Generate(nBits)
	if err != nil {
		errorThrow(err)
		return C.KeyPair{C.CString(""), C.CString("")}

	}
	return C.KeyPair{C.CString(result.PrivateKey), C.CString(result.PublicKey)}

}

//export Hash
func Hash(message, name *C.char) *C.char {
	result, err := instance.Hash(C.GoString(message), C.GoString(name))
	if err != nil {
		errorThrow(err)
		return nil
	}
	return C.CString(result)
}

//export Base64
func Base64(message *C.char) *C.char {
	result, err := instance.Base64(C.GoString(message))
	if err != nil {
		errorThrow(err)
		return nil
	}
	return C.CString(result)
}

//export SignPKCS1v15
func SignPKCS1v15(message, hashName, privateKey *C.char) *C.char {
	result, err := instance.SignPKCS1v15(C.GoString(message), C.GoString(hashName), C.GoString(privateKey))
	if err != nil {
		errorThrow(err)
		return nil
	}
	return C.CString(result)
}

//export SignPSS
func SignPSS(message, hashName, saltLengthName, privateKey *C.char) *C.char {
	result, err := instance.SignPSS(C.GoString(message), C.GoString(hashName), C.GoString(saltLengthName), C.GoString(privateKey))
	if err != nil {
		errorThrow(err)
		return nil
	}
	return C.CString(result)
}

//export VerifyPKCS1v15
func VerifyPKCS1v15(signature, message, hashName, publicKey *C.char) *C.char {
	result, err := instance.VerifyPKCS1v15(C.GoString(signature), C.GoString(message), C.GoString(hashName), C.GoString(publicKey))
	if err != nil {
		errorThrow(err)
		return nil
	}
	if result {
		return C.CString("1")
	}
	return C.CString("")
}

//export VerifyPSS
func VerifyPSS(signature, message, hashName, saltLengthName, publicKey *C.char) *C.char {
	result, err := instance.VerifyPSS(C.GoString(signature), C.GoString(message), C.GoString(hashName), C.GoString(saltLengthName), C.GoString(publicKey))
	if err != nil {
		errorThrow(err)
		return nil
	}
	if result {
		return C.CString("1")
	}
	return C.CString("")
}

func main() {}
