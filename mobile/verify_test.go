package rsa

import "testing"

func TestRSA_Verify(t *testing.T) {

	instance := NewRSA()
	hash, err := instance.Hash(inputMessage, "sha512")
	if err != nil {
		t.Fatal(err)
	}

	output, err := instance.Verify(signed, hash, "sha512", p12, passphrase)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}
