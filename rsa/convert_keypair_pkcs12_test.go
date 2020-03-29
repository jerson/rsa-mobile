package rsa

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestFastRSA_ConvertKeyPairToPKCS12(t *testing.T) {
	instance := NewFastRSA()
	output, err := instance.ConvertKeyPairToPKCS12(privateKey, publicKey, certificate, passphrase)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}

func TestFastRSA_ConvertKeyPairToPKCS12Complete(t *testing.T) {
	instance := NewFastRSA()
	pkcs12, err := instance.ConvertKeyPairToPKCS12(privateKey, publicKey, certificate, passphrase)
	if err != nil {
		t.Fatal(err)
	}

	output, err := instance.ConvertPKCS12ToKeyPair(pkcs12, passphrase)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, publicKey, output.PublicKey)
	assert.Equal(t, privateKey, output.PrivateKey)
	assert.Equal(t, certificate, output.Certificate)

	encoded, _ := json.MarshalIndent(output, "", " ")
	t.Log("output:", string(encoded))
}

func TestFastRSA_ConvertKeyPairToPKCS12WithoutCert(t *testing.T) {
	instance := NewFastRSA()
	output, err := instance.ConvertKeyPairToPKCS12(privateKey, publicKey, "", passphrase)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}

func TestFastRSA_ConvertKeyPairToPKCS12CompleteWithoutCert(t *testing.T) {
	instance := NewFastRSA()
	pkcs12, err := instance.ConvertKeyPairToPKCS12(privateKey, publicKey, "", passphrase)
	if err != nil {
		t.Fatal(err)
	}

	output, err := instance.ConvertPKCS12ToKeyPair(pkcs12, passphrase)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, publicKey, output.PublicKey)
	assert.Equal(t, privateKey, output.PrivateKey)

	encoded, _ := json.MarshalIndent(output, "", " ")
	t.Log("output:", string(encoded))
}
