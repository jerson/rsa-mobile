package rsa

import "testing"

func TestFastRSA_SignPSS(t *testing.T) {

	instance := NewFastRSA()

	output, err := instance.SignPSS(inputMessage, "sha512", p12, passphrase)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}
