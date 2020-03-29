package rsa

import (
	"crypto/rand"
	cryptoRSA "crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"software.sslmate.com/src/go-pkcs12"
	"time"
)

func (r *FastRSA) ConvertKeyPairToPKCS12(privateKey, certificate, passphrase string) (string, error) {

	privateKeyCertKeyBase, err := r.readPrivateKey(privateKey)
	if err != nil {
		return "", err
	}
	privateKeyCert := toCryptoRSAPrivateKey(privateKeyCertKeyBase)

	var certificateBytes []byte
	if certificate == "" {
		certificateBytes, err = createDefaultCertificate(privateKeyCert)
		if err != nil {
			return "", err
		}
	} else {
		certificateBlock, _ := pem.Decode([]byte(certificate))
		certificateBytes = certificateBlock.Bytes
	}

	certificateCert, err := x509.ParseCertificate(certificateBytes)
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

func createDefaultCertificate(privateKeyCert *cryptoRSA.PrivateKey) ([]byte, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}
	notBefore := time.Now()
	notAfter := notBefore.Add(time.Hour * 24 * 365)
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{""},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certificateCreated, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKeyCert.PublicKey, privateKeyCert)
	if err != nil {
		return nil, err
	}

	return certificateCreated, nil
}
