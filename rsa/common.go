package rsa

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	cryptoRSA "crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"github.com/keybase/go-crypto/pkcs12"
	"github.com/keybase/go-crypto/rsa"
)

func (r *FastRSA) readPrivateKey(privateKey string) (*rsa.PrivateKey, error) {

	privateBlock, _ := pem.Decode([]byte(privateKey))
	privateKeyCert, err := x509.ParsePKCS1PrivateKey(privateBlock.Bytes)
	if err != nil {
		return nil, err
	}

	return toKeyBaseRSAPrivateKey(privateKeyCert), nil
}

func (r *FastRSA) readPublicKey(publicKey string) (*rsa.PublicKey, error) {

	publicBlock, _ := pem.Decode([]byte(publicKey))
	publicKeyCert, err := x509.ParsePKCS1PublicKey(publicBlock.Bytes)
	if err != nil {
		return nil, err
	}
	return toKeyBaseRSAPublicKey(publicKeyCert), nil
}

func (r *FastRSA) readPKCS12(data, passphrase string) (interface{}, *x509.Certificate, error) {

	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, nil, err
	}
	private, certificate, err := pkcs12.Decode(decoded, passphrase)
	if err != nil {
		return nil, certificate, err
	}

	err = r.validatePrivateKey(private)
	if err != nil {
		return nil, certificate, err
	}

	return private, certificate, nil
}

func (r *FastRSA) validatePrivateKey(privateKey interface{}) error {

	switch privateKey.(type) {
	case *cryptoRSA.PrivateKey:
		return privateKey.(*cryptoRSA.PrivateKey).Validate()
	case *rsa.PrivateKey:
		return toCryptoRSAPrivateKey(privateKey.(*rsa.PrivateKey)).Validate()
	case *ecdsa.PrivateKey:
		return nil
	case *ed25519.PrivateKey:
		return nil
	default:
		return nil
	}

}

//func (r *FastRSA) readPrivateKeyGeneric(privateKey string) (interface{}, error) {
//
//	privateBlock, _ := pem.Decode([]byte(privateKey))
//
//	if privateKeyCert, err := x509.ParsePKCS1PrivateKey(privateBlock.Bytes); err == nil {
//		return toKeyBaseRSAPrivateKey(privateKeyCert), nil
//	}
//	if privateKeyCert, err := x509.ParsePKCS8PrivateKey(privateBlock.Bytes); err == nil {
//		return privateKeyCert, nil
//	}
//	if privateKeyCert, err := x509.ParseECPrivateKey(privateBlock.Bytes); err == nil {
//		return privateKeyCert, nil
//	}
//
//	return nil, errors.New("x509: unknown format")
//}
//
//func (r *FastRSA) readPublicKeyGeneric(publicKey string) (interface{}, error) {
//
//	publicBlock, _ := pem.Decode([]byte(publicKey))
//
//	if publicKeyCert, err := x509.ParsePKCS1PublicKey(publicBlock.Bytes); err == nil {
//		return toKeyBaseRSAPublicKey(publicKeyCert), nil
//	}
//	if publicKeyCert, err := x509.ParsePKIXPublicKey(publicBlock.Bytes); err == nil {
//		return publicKeyCert, nil
//	}
//
//	return nil, errors.New("x509: unknown format")
//}
