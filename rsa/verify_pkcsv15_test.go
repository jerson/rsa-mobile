package rsa

import (
	"testing"
)

func TestFastRSA_VerifyPKCS1v15(t *testing.T) {

	instance := NewFastRSA()

	output, err := instance.VerifyPKCS1v15(signed, inputMessage, "sha512", publicKey)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}
