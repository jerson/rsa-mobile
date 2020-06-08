package rsa

import (
	"testing"
)

func TestFastRSA_MetadataPublicKey(t *testing.T) {

	instance := NewFastRSA()
	output, err := instance.MetadataPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}

func TestFastRSA_MetadataPublicKeyGenerated(t *testing.T) {

	instance := NewFastRSA()
	data, err := instance.Generate(2048)
	if err != nil {
		t.Fatal(err)
	}
	output, err := instance.MetadataPublicKey(data.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}

func TestFastRSA_MetadataPrivateKey(t *testing.T) {

	instance := NewFastRSA()
	output, err := instance.MetadataPrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}

func TestFastRSA_MetadataPrivateKeyGenerated(t *testing.T) {

	instance := NewFastRSA()
	data, err := instance.Generate(2048)
	if err != nil {
		t.Fatal(err)
	}
	output, err := instance.MetadataPrivateKey(data.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}
