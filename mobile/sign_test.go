package rsa

import "testing"

func TestRSA_Sign(t *testing.T) {

	instance := NewFastRSA()
	hash, err := instance.Hash(inputMessage, "sha512")
	if err != nil {
		t.Fatal(err)
	}

	output, err := instance.Sign(hash, "sha512", p12, passphrase)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}
