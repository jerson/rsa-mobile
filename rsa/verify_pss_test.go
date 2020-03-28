package rsa

import "testing"

func TestFastRSA_VerifyPSS(t *testing.T) {

	instance := NewFastRSA()

	output, err := instance.VerifyPSS(signed_pss, inputMessage, "sha512", publicKey)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}
