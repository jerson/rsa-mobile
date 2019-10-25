package rsa

import "testing"

func TestRSA_Encrypt(t *testing.T) {

	instance := NewRSA()
	output, err := instance.Encrypt(inputMessage, p12, passphrase)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}
