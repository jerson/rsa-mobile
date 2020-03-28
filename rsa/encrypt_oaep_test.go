package rsa

import "testing"

func TestFastRSA_EncryptOAEP(t *testing.T) {

	instance := NewFastRSA()
	output, err := instance.EncryptOAEP(inputMessage, "", "sha256", publicKey)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}
