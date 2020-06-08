package main

// #include <stdint.h>
// typedef struct { char *privateKey; char *publicKey; } KeyPair;
// typedef struct { char *privateKey; char *publicKey; char *certificate; } PKCS12KeyPair;
// typedef struct { int bitLen; int size; char *error; } PrivateKeyInfo;
// typedef struct { int bitLen; int size; int e; } PublicKeyInfo;
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
func DecryptOAEPBytes(ciphertext unsafe.Pointer, ciphertextSize C.int, label, hashName, privateKey *C.char) (unsafe.Pointer, C.int) {
	result, err := instance.DecryptOAEPBytes(C.GoBytes(ciphertext, ciphertextSize), C.GoString(label), C.GoString(hashName), C.GoString(privateKey))
	if err != nil {
		errorThrow(err)
		return nil, C.int(0)
	}
	return C.CBytes(result), C.int(len(result))
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

//export DecryptPKCS1v15Bytes
func DecryptPKCS1v15Bytes(ciphertext unsafe.Pointer, ciphertextSize C.int, privateKey *C.char) (unsafe.Pointer, C.int) {
	result, err := instance.DecryptPKCS1v15Bytes(C.GoBytes(ciphertext, ciphertextSize), C.GoString(privateKey))
	if err != nil {
		errorThrow(err)
		return C.CBytes(result), C.int(0)
	}
	return C.CBytes(result), C.int(len(result))
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

//export EncryptOAEPBytes
func EncryptOAEPBytes(message unsafe.Pointer, messageSize C.int, label, hashName, publicKey *C.char) (unsafe.Pointer, C.int) {
	result, err := instance.EncryptOAEPBytes(C.GoBytes(message, messageSize), C.GoString(label), C.GoString(hashName), C.GoString(publicKey))
	if err != nil {
		errorThrow(err)
		return nil, C.int(0)
	}
	return C.CBytes(result), C.int(len(result))
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

//export EncryptPKCS1v15Bytes
func EncryptPKCS1v15Bytes(message unsafe.Pointer, messageSize C.int, publicKey *C.char) (unsafe.Pointer, C.int) {
	result, err := instance.EncryptPKCS1v15Bytes(C.GoBytes(message, messageSize), C.GoString(publicKey))
	if err != nil {
		errorThrow(err)
		return nil, C.int(0)
	}
	return C.CBytes(result), C.int(len(result))
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

//export MetadataPrivateKey
func MetadataPrivateKey(privateKey *C.char) C.PrivateKeyInfo {
	result, err := instance.MetadataPrivateKey(C.GoString(privateKey))
	if err != nil {
		errorThrow(err)
		return C.PrivateKeyInfo{C.int(0), C.int(0), C.CString("")}

	}
	return C.PrivateKeyInfo{C.int(result.BitLen), C.int(result.Size), C.CString(result.Error)}
}

//export MetadataPublicKey
func MetadataPublicKey(publicKey *C.char) C.PublicKeyInfo {
	result, err := instance.MetadataPublicKey(C.GoString(publicKey))
	if err != nil {
		errorThrow(err)
		return C.PublicKeyInfo{C.int(0), C.int(0), C.int(0)}

	}
	return C.PublicKeyInfo{C.int(result.BitLen), C.int(result.Size), C.int(result.E)}
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

//export SignPKCS1v15Bytes
func SignPKCS1v15Bytes(message unsafe.Pointer, messageSize C.int, hashName, privateKey *C.char) (unsafe.Pointer, C.int) {
	result, err := instance.SignPKCS1v15Bytes(C.GoBytes(message, messageSize), C.GoString(hashName), C.GoString(privateKey))
	if err != nil {
		errorThrow(err)
		return nil, C.int(0)
	}
	return C.CBytes(result), C.int(len(result))
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

//export SignPSSBytes
func SignPSSBytes(message unsafe.Pointer, messageSize C.int, hashName, saltLengthName, privateKey *C.char) (unsafe.Pointer, C.int) {
	result, err := instance.SignPSSBytes(C.GoBytes(message, messageSize), C.GoString(hashName), C.GoString(saltLengthName), C.GoString(privateKey))
	if err != nil {
		errorThrow(err)
		return nil, C.int(0)
	}
	return C.CBytes(result), C.int(len(result))
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

//export VerifyPKCS1v15Bytes
func VerifyPKCS1v15Bytes(signature unsafe.Pointer, signatureSize C.int, message unsafe.Pointer, messageSize C.int, hashName, publicKey *C.char) *C.char {
	result, err := instance.VerifyPKCS1v15Bytes(C.GoBytes(signature, signatureSize), C.GoBytes(message, messageSize), C.GoString(hashName), C.GoString(publicKey))
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

//export VerifyPSSBytes
func VerifyPSSBytes(signature unsafe.Pointer, signatureSize C.int, message unsafe.Pointer, messageSize C.int, hashName, saltLengthName, publicKey *C.char) *C.char {
	result, err := instance.VerifyPSSBytes(C.GoBytes(signature, signatureSize), C.GoBytes(message, messageSize), C.GoString(hashName), C.GoString(saltLengthName), C.GoString(publicKey))
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
