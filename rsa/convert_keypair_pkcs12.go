package rsa

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"software.sslmate.com/src/go-pkcs12"
)

func (r *FastRSA) ConvertKeyPairToPKCS12(privateKey, publicKey, certificate, passphrase string) (string, error) {

	privateKeyCertKeyBase, err := r.readPrivateKey(privateKey)
	if err != nil {
		return "", err
	}
	privateKeyCert := toCryptoRSAPrivateKey(privateKeyCertKeyBase)

	if publicKey != "" {
		publicKeyCertKeyBase, err := r.readPublicKey(publicKey)
		if err != nil {
			return "", err
		}
		publicKeyCert := toCryptoRSAPublicKey(publicKeyCertKeyBase)
		if publicKeyCert != nil {
			privateKeyCert.PublicKey = *publicKeyCert
		}
	}

	certificateBlock, _ := pem.Decode([]byte(certificate))
	certificateCert, err := x509.ParseCertificate(certificateBlock.Bytes)
	if err != nil {
		return "", err
	}

	encoded, err := pkcs12.Encode(rand.Reader, privateKeyCert, certificateCert, nil, passphrase)
	if err != nil {
		return "", err
	}

	output, err := encodeToPEMBase64(encoded)
	if err != nil {
		return "", err
	}

	return string(output), nil
}
