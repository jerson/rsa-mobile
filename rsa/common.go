package rsa

import (
	"crypto/rsa"
	"fmt"
	"golang.org/x/crypto/pkcs12"

	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
)

func (r *FastRSA) readPrivateKey(privateKey string) (*rsa.PrivateKey, error) {

	block, _ := pem.Decode([]byte(privateKey))
	if block == nil {
		return nil, fmt.Errorf("invalid private key")
	}

	switch block.Type {
	case string(HeaderPrivateKeyPKCS1):
		if privateKeyCert, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
			return privateKeyCert, nil
		}
	case string(HeaderPrivateKeyPKCS8):
		if privateKeyCert, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			return privateKeyCert.(*rsa.PrivateKey), nil
		}
	}

	// TODO remove this in the future because we need to use block.type instead
	if privateKeyCert, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return privateKeyCert, nil
	}
	if privateKeyCert, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return privateKeyCert.(*rsa.PrivateKey), nil
	}

	return nil, fmt.Errorf("x509: unknown format for privateKey: %s", block.Type)
}

func (r *FastRSA) readPublicKey(publicKey string) (*rsa.PublicKey, error) {

	block, _ := pem.Decode([]byte(publicKey))
	if block == nil {
		return nil, errors.New("invalid public key")
	}

	switch block.Type {
	case string(HeaderPublicKeyPKCS1):
		if publicKeyCert, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
			return publicKeyCert, nil
		}
	case string(HeaderPublicKeyPKIX):
		if publicKeyCert, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
			return publicKeyCert.(*rsa.PublicKey), nil
		}
	}

	// TODO remove this in the future because we need to use block.type instead
	if publicKeyCert, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return publicKeyCert, nil
	}
	if publicKeyCert, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		return publicKeyCert.(*rsa.PublicKey), nil
	}

	return nil, fmt.Errorf("x509: unknown format for publicKey: %s", block.Type)
}

func (r *FastRSA) readPKCS12(data, password string) (interface{}, *x509.Certificate, error) {

	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, nil, err
	}
	private, certificate, err := pkcs12.Decode(decoded, password)
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
	case *rsa.PrivateKey:
		return privateKey.(*rsa.PrivateKey).Validate()
	default:
		return nil
	}

}
