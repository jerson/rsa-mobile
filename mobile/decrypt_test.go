package rsa

import "testing"

func TestRSA_Decrypt(t *testing.T) {

	instance := NewRSA()
	output, err := instance.Decrypt(message, p12, passphrase)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}
