package rsa

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"software.sslmate.com/src/go-pkcs12"
)

func (r *FastRSA) ConvertKeyPairToPKCS12(privateKey, publicKey, certificate, passphrase string) (string, error) {

	privateBlock, _ := pem.Decode([]byte(privateKey))
	privateKeyCert, err := x509.ParsePKCS1PrivateKey(privateBlock.Bytes)
	if err != nil {
		return "", err
	}

	publicBlock, _ := pem.Decode([]byte(publicKey))
	publicKeyCert, err := x509.ParsePKCS1PublicKey(publicBlock.Bytes)
	if err != nil {
		return "", err
	}
	if publicKeyCert != nil {
		privateKeyCert.PublicKey = *publicKeyCert
	}

	//ert, err := tls.X509KeyPair(publicBlock.Bytes, privateBlock.Bytes)

	certificateBlock, _ := pem.Decode([]byte(certificate))
	certificateCert, err := x509.ParseCertificate(certificateBlock.Bytes)
	if err != nil {
		return "", err
	}

	encoded, err := pkcs12.Encode(rand.Reader, privateKeyCert, certificateCert, nil, passphrase)
	if err != nil {
		return "", err
	}

	output := base64.StdEncoding.EncodeToString(encoded)

	return output, nil
}
