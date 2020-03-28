package rsa

import "testing"

func TestFastRSA_SignPKCS1v15(t *testing.T) {

	instance := NewFastRSA()

	output, err := instance.SignPKCS1v15(inputMessage, "sha512", privateKey)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}
