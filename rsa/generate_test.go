package rsa

import (
	"testing"
)

func TestFastRSA_Generate1024(t *testing.T) {

	instance := NewFastRSA()
	output, err := instance.Generate(1024, &EncodeOptions{})
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}
func TestFastRSA_Generate2048(t *testing.T) {

	instance := NewFastRSA()
	output, err := instance.Generate(2048, &EncodeOptions{})
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}
func TestFastRSA_Generate4096(t *testing.T) {

	instance := NewFastRSA()
	output, err := instance.Generate(4096, &EncodeOptions{
		PublicKeyFormat:  "pkcs1",
		PrivateKeyFormat: "pkcs1",
	})
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}
func TestFastRSA_Generate4096Options(t *testing.T) {

	instance := NewFastRSA()
	output, err := instance.Generate(4096, &EncodeOptions{
		PublicKeyFormat:  "pkix",
		PrivateKeyFormat: "pkcs8",
	})
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}
