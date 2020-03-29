package rsa

import (
	"testing"
)

func TestFastRSA_VerifyPSS(t *testing.T) {

	instance := NewFastRSA()

	output, err := instance.VerifyPSS(signedPSS, inputMessage, "sha512", "equalsHash", publicKey)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}
