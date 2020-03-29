package rsa

import (
	"bytes"
	"crypto"
	"crypto/md5"
	cryptoRSA "crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/keybase/go-crypto/rsa"
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

func getPrivateKeyFormatType(format string) PrivateKeyFormatType {
	switch format {
	case "pkcs8":
		return PrivateKeyFormatTypePKCS8
	case "pkcs1":
		return PrivateKeyFormatTypePKCS1
	default:
		return PrivateKeyFormatTypePKCS1
	}
}

func getPublicKeyFormatType(format string) PublicKeyFormatType {
	switch format {
	case "pkix":
		return PublicKeyFormatTypePKIX
	case "pkcs1":
		return PublicKeyFormatTypePKCS1
	default:
		return PublicKeyFormatTypePKCS1
	}
}

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

func toCryptoRSAPrivateKey(keybasePrivateKey *rsa.PrivateKey) *cryptoRSA.PrivateKey {

	var crtValues []cryptoRSA.CRTValue
	for _, value := range keybasePrivateKey.Precomputed.CRTValues {
		crtValues = append(crtValues, cryptoRSA.CRTValue{
			Exp:   value.Exp,
			Coeff: value.Coeff,
			R:     value.R,
		})
	}

	privateKey := &cryptoRSA.PrivateKey{
		PublicKey: *toCryptoRSAPublicKey(&keybasePrivateKey.PublicKey),
		D:         keybasePrivateKey.D,
		Primes:    keybasePrivateKey.Primes,
		Precomputed: cryptoRSA.PrecomputedValues{
			Dp:        keybasePrivateKey.Precomputed.Dp,
			Dq:        keybasePrivateKey.Precomputed.Dq,
			Qinv:      keybasePrivateKey.Precomputed.Qinv,
			CRTValues: crtValues,
		},
	}
	return privateKey
}

func toCryptoRSAPublicKey(publicKey *rsa.PublicKey) *cryptoRSA.PublicKey {
	return &cryptoRSA.PublicKey{
		N: publicKey.N,
		E: int(publicKey.E),
	}
}

func toKeyBaseRSAPrivateKey(cryptoPrivateKey *cryptoRSA.PrivateKey) *rsa.PrivateKey {

	var crtValues []rsa.CRTValue
	for _, value := range cryptoPrivateKey.Precomputed.CRTValues {
		crtValues = append(crtValues, rsa.CRTValue{
			Exp:   value.Exp,
			Coeff: value.Coeff,
			R:     value.R,
		})
	}

	privateKey := &rsa.PrivateKey{
		PublicKey: *toKeyBaseRSAPublicKey(&cryptoPrivateKey.PublicKey),
		D:         cryptoPrivateKey.D,
		Primes:    cryptoPrivateKey.Primes,
		Precomputed: rsa.PrecomputedValues{
			Dp:        cryptoPrivateKey.Precomputed.Dp,
			Dq:        cryptoPrivateKey.Precomputed.Dq,
			Qinv:      cryptoPrivateKey.Precomputed.Qinv,
			CRTValues: crtValues,
		},
	}
	return privateKey
}

func toKeyBaseRSAPublicKey(publicKey *cryptoRSA.PublicKey) *rsa.PublicKey {
	return &rsa.PublicKey{
		N: publicKey.N,
		E: int64(publicKey.E),
	}
}

func encodePublicKey(publicKey interface{}, formatType PublicKeyFormatType) ([]byte, error) {

	var pemBytes []byte
	var err error

	var public *cryptoRSA.PublicKey
	switch publicKey.(type) {
	case *cryptoRSA.PublicKey:
		public = publicKey.(*cryptoRSA.PublicKey)
		break
	case *rsa.PublicKey:
		public = toCryptoRSAPublicKey(publicKey.(*rsa.PublicKey))
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
	return pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pemBytes,
		},
	), nil
}

func encodePrivateKey(privateKey interface{}, formatType PrivateKeyFormatType) ([]byte, error) {

	var pemBytes []byte
	var err error

	var private *cryptoRSA.PrivateKey
	switch privateKey.(type) {
	case *cryptoRSA.PrivateKey:
		private = privateKey.(*cryptoRSA.PrivateKey)
		break
	case *rsa.PrivateKey:
		private = toCryptoRSAPrivateKey(privateKey.(*rsa.PrivateKey))
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

	return pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: pemBytes,
		},
	), nil
}

func publicFromPrivate(privateKey interface{}) (interface{}, error) {
	switch privateKey.(type) {
	case *cryptoRSA.PrivateKey:
		return &privateKey.(*cryptoRSA.PrivateKey).PublicKey, nil
	case *rsa.PrivateKey:
		return &toCryptoRSAPrivateKey(privateKey.(*rsa.PrivateKey)).PublicKey, nil
	default:
		return nil, fmt.Errorf("not found: %T", privateKey)
	}

}

func encodeCertificate(certificate *x509.Certificate) []byte {

	return pem.EncodeToMemory(
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
	b64.Close()
	breaker.Close()

	return out.Bytes(), nil

}
