package rsa

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/md5"
	"crypto/rsa"

	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"hash"
)

type PublicKeyFormatType int

const (
	PublicKeyFormatTypePKCS1 PublicKeyFormatType = iota
	PublicKeyFormatTypePKIX
)

type PrivateKeyFormatType int

const (
	PrivateKeyFormatTypePKCS1 PrivateKeyFormatType = iota
	PrivateKeyFormatTypePKCS8
)

type HeaderPublicKeyType string

const (
	HeaderPublicKeyPKCS1 = HeaderPublicKeyType("RSA PUBLIC KEY")
	HeaderPublicKeyPKIX  = HeaderPublicKeyType("PUBLIC KEY")
)

type HeaderPrivateKeyType string

const (
	HeaderPrivateKeyPKCS1 = HeaderPrivateKeyType("RSA PRIVATE KEY")
	HeaderPrivateKeyPKCS8 = HeaderPrivateKeyType("PRIVATE KEY")
)

func getSaltLength(length string) int {
	switch length {
	case "auto":
		return rsa.PSSSaltLengthAuto
	case "equalsHash":
		return rsa.PSSSaltLengthEqualsHash
	default:
		return rsa.PSSSaltLengthAuto
	}
}

func getHashType(hash string) crypto.Hash {
	switch hash {
	case "sha256":
		return crypto.SHA256
	case "sha224":
		return crypto.SHA224
	case "sha384":
		return crypto.SHA384
	case "sha512":
		return crypto.SHA512
	case "sha1":
		return crypto.SHA1
	case "md5":
		return crypto.MD5
	default:
		return crypto.SHA256
	}
}

func getHashInstance(name string) hash.Hash {
	switch name {
	case "md5":
		return md5.New()
	case "sha1":
		return sha1.New()
	case "sha224":
		return sha512.New512_224()
	case "sha256":
		return sha256.New()
	case "sha384":
		return sha512.New384()
	case "sha512":
		return sha512.New()
	default:
		return sha256.New()
	}
}
func getPEMCipher(name string) x509.PEMCipher {
	switch name {
	case "des":
		return x509.PEMCipherDES
	case "3des":
		return x509.PEMCipher3DES
	case "aes128":
		return x509.PEMCipherAES128
	case "aes192":
		return x509.PEMCipherAES192
	case "aes256":
		return x509.PEMCipherAES256
	default:
		return x509.PEMCipherAES256
	}
}

func getPublicKeyHeaderByType(formatType PublicKeyFormatType) string {
	switch formatType {
	case PublicKeyFormatTypePKIX:
		return string(HeaderPublicKeyPKIX)
	case PublicKeyFormatTypePKCS1:
		fallthrough
	default:
		return string(HeaderPublicKeyPKCS1)
	}
}

func getPrivateKeyHeaderByType(formatType PrivateKeyFormatType) string {
	switch formatType {
	case PrivateKeyFormatTypePKCS8:
		return string(HeaderPrivateKeyPKCS8)
	case PrivateKeyFormatTypePKCS1:
		fallthrough
	default:
		return string(HeaderPrivateKeyPKCS1)
	}
}

func encodePublicKey(publicKey interface{}, formatType PublicKeyFormatType) ([]byte, error) {

	var pemBytes []byte
	var err error

	var public *rsa.PublicKey
	switch publicKey.(type) {
	case *rsa.PublicKey:
		public = publicKey.(*rsa.PublicKey)
		break
	}

	switch formatType {
	case PublicKeyFormatTypePKCS1:
		pemBytes = x509.MarshalPKCS1PublicKey(public)
		break
	case PublicKeyFormatTypePKIX:
		pemBytes, err = x509.MarshalPKIXPublicKey(public)
		if err != nil {
			return nil, err
		}
		break
	}
	return encodePem(
		&pem.Block{
			Type:  getPublicKeyHeaderByType(formatType),
			Bytes: pemBytes,
		},
	)
}

func encodePrivateKey(privateKey interface{}, formatType PrivateKeyFormatType) ([]byte, error) {

	var pemBytes []byte
	var err error

	var private *rsa.PrivateKey
	switch privateKey.(type) {
	case *rsa.PrivateKey:
		private = privateKey.(*rsa.PrivateKey)
		break
	}

	switch formatType {
	case PrivateKeyFormatTypePKCS1:
		pemBytes = x509.MarshalPKCS1PrivateKey(private)
		break
	case PrivateKeyFormatTypePKCS8:
		pemBytes, err = x509.MarshalPKCS8PrivateKey(private)
		if err != nil {
			return nil, err
		}

		break
	}

	return encodePem(
		&pem.Block{
			Type:  getPrivateKeyHeaderByType(formatType),
			Bytes: pemBytes,
		},
	)
}

// encodePem thanks to @patachi
func encodePem(b *pem.Block) ([]byte, error) {
	buf := new(bytes.Buffer)
	w := bufio.NewWriter(buf)
	if err := pem.Encode(w, b); err != nil {
		return nil, err
	}
	if err := w.Flush(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func publicFromPrivate(privateKey interface{}) (interface{}, error) {
	switch privateKey.(type) {
	case *rsa.PrivateKey:
		return &privateKey.(*rsa.PrivateKey).PublicKey, nil
	default:
		return nil, fmt.Errorf("not found: %T", privateKey)
	}

}

func encodeCertificate(certificate *x509.Certificate) ([]byte, error) {
	return encodePem(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certificate.Raw,
		},
	)
}

func encodeToPEMBase64(input []byte) ([]byte, error) {

	var out bytes.Buffer
	var breaker lineBreaker
	breaker.out = &out

	b64 := base64.NewEncoder(base64.StdEncoding, &breaker)
	if _, err := b64.Write(input); err != nil {
		return nil, err
	}
	err := b64.Close()
	if err != nil {
		return nil, err
	}
	err = breaker.Close()
	if err != nil {
		return nil, err
	}

	return out.Bytes(), nil

}
